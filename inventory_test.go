package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageInventoryResolutionAndMultipleBinaries(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Mock Cargo receipt with multiple binaries
	cargoBinDir := filepath.Join(tmpHome, ".cargo", "bin")
	os.MkdirAll(cargoBinDir, 0755)
	os.WriteFile(filepath.Join(cargoBinDir, "ripgrep"), []byte("rg"), 0755)
	os.WriteFile(filepath.Join(cargoBinDir, "rg"), []byte("rg"), 0755)

	cratesFile := filepath.Join(tmpHome, ".cargo", ".crates2.json")
	cratesJSON := `{
		"installs": {
			"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {
				"bins": ["ripgrep", "rg"]
			}
		}
	}`
	os.WriteFile(cratesFile, []byte(cratesJSON), 0644)

	// Mock npm global modules
	npmDir := filepath.Join(tmpHome, ".config", "nvm", "versions", "node", "v18.0.0", "lib", "node_modules", "typescript")
	os.MkdirAll(npmDir, 0755)
	os.WriteFile(filepath.Join(npmDir, "package.json"), []byte(`{"name":"typescript","version":"5.0.0"}`), 0644)

	inv := loadPackageInventory()

	if inv.CargoCrates["ripgrep"] != "ripgrep" || inv.CargoCrates["rg"] != "ripgrep" {
		t.Errorf("Cargo multiple binaries mapping failed: ripgrep=%s, rg=%s", inv.CargoCrates["ripgrep"], inv.CargoCrates["rg"])
	}

	if inv.NpmPackages["typescript"] != "typescript" {
		t.Errorf("npm package mapping failed: typescript=%s", inv.NpmPackages["typescript"])
	}
}

func TestFormatUninstallArgsAllPackageManagers(t *testing.T) {
	inv := &PackageInventory{
		CargoCrates:  map[string]string{"rg": "ripgrep"},
		PipxVenvs:    map[string]string{"black": "black"},
		NpmPackages:  map[string]string{"typescript": "typescript"},
		DotnetTools:  map[string]string{"csharp-ls": "csharp-ls"},
		ComposerPkgs: map[string]string{"vendor/pkg": "vendor/pkg"},
		ZvmVersions:  map[string]string{"master": "master"},
		SdkmanCands:  map[string]bool{"java/17.0.2-open": true},
	}

	tests := []struct {
		category string
		name     string
		path     string
		expected string
	}{
		{"UNUSED (Cargo)", "rg", "/home/user/.cargo/bin/rg", "cargo uninstall ripgrep"},
		{"UNUSED (pipx)", "black", "/home/user/.local/pipx/venvs/black/bin/black", "pipx uninstall black"},
		{"UNUSED (npm)", "typescript", "/home/user/.nvm/versions/node/v18.0.0/bin/typescript", "npm uninstall -g typescript"},
		{"UNUSED (Dotnet)", "csharp-ls", "/home/user/.dotnet/tools/csharp-ls", "dotnet tool uninstall -g csharp-ls"},
		{"UNUSED (Composer)", "vendor/pkg", "/home/user/.config/composer/vendor/pkg", "composer global remove vendor/pkg"},
		{"UNUSED (ZVM)", "master", "/home/user/.zvm/master", "zvm remove master"},
		{"UNUSED (SDKMAN)", "17.0.2-open", "/home/user/.sdkman/candidates/java/17.0.2-open", "sdk uninstall java 17.0.2-open"},
	}

	for _, tt := range tests {
		args := formatUninstallArgs(tt.category, tt.name, tt.path, inv)
		if len(args) == 0 {
			t.Errorf("formatUninstallArgs for %s returned empty; expected %s", tt.category, tt.expected)
			continue
		}
		got := strings.Join(args, " ")
		if got != tt.expected {
			t.Errorf("formatUninstallArgs for category %s: expected '%s'; got '%s'", tt.category, tt.expected, got)
		}
	}

	// Negative unmapped fixture returns empty
	unmappedArgs := formatUninstallArgs("UNUSED (Cargo)", "unmapped-crate", "/home/user/.cargo/bin/unmapped-crate", inv)
	if len(unmappedArgs) != 0 {
		t.Errorf("Expected empty uninstallArgs for unmapped package; got %v", unmappedArgs)
	}
}
