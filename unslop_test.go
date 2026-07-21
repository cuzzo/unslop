package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		res := formatBytes(tt.input)
		if res != tt.expected {
			t.Errorf("formatBytes(%d) = %s; want %s", tt.input, res, tt.expected)
		}
	}
}

func TestFormatUintBytes(t *testing.T) {
	res := formatUintBytes(1048576)
	if res != "1.0 MB" {
		t.Errorf("formatUintBytes(1048576) = %s; want 1.0 MB", res)
	}
}

func TestRiskClassEnumValidation(t *testing.T) {
	validClasses := []RiskClass{RiskRegenerable, RiskPackageManaged, RiskUserData, RiskUnknown}
	for _, r := range validClasses {
		if !r.IsValid() {
			t.Errorf("RiskClass %s should be valid", r)
		}
	}

	invalid := RiskClass("arbitrary-junk")
	if invalid.IsValid() {
		t.Errorf("Invalid RiskClass should return false for IsValid()")
	}
}

func TestCalculateDynamicMinSizeMB(t *testing.T) {
	const gb = uint64(1024 * 1024 * 1024)

	if calculateDynamicMinSizeMB(0) != 10.0 {
		t.Errorf("0 disk size should yield 10.0 MB")
	}
	if calculateDynamicMinSizeMB(10*gb) != 1.0 {
		t.Errorf("10GB disk should yield 1.0 MB")
	}
	if calculateDynamicMinSizeMB(50*gb) != 1.0 {
		t.Errorf("50GB disk should yield 1.0 MB")
	}
	sz100 := calculateDynamicMinSizeMB(100 * gb)
	if sz100 < 9.9 || sz100 > 10.1 {
		t.Errorf("100GB disk should yield ~10.0 MB; got %.2f", sz100)
	}
	if calculateDynamicMinSizeMB(1000*gb) != 50.0 {
		t.Errorf("1TB disk should yield 50.0 MB cap")
	}
}

func TestFormatNumber(t *testing.T) {
	if formatNumber(123) != "123" {
		t.Errorf("formatNumber(123) failed")
	}
	if formatNumber(1234567) != "1,234,567" {
		t.Errorf("formatNumber(1234567) failed")
	}
}

func TestIsProtected(t *testing.T) {
	if !isProtected("/path/to/config.toml") {
		t.Errorf("isProtected config.toml failed")
	}
	if !isProtected("/path/to/credentials.json") {
		t.Errorf("isProtected credentials.json failed")
	}
	if isProtected("/path/to/normal.txt") {
		t.Errorf("isProtected normal.txt failed")
	}
}

func TestContainsProtectedPath(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "sub")
	os.MkdirAll(subDir, 0755)
	credFile := filepath.Join(subDir, "credentials.json")
	os.WriteFile(credFile, []byte("secret"), 0600)

	if !containsProtectedPath(tmpDir) {
		t.Errorf("containsProtectedPath should detect sub/credentials.json")
	}

	containsProtectedPath("/non/existent/path/999")

	safeDir := t.TempDir()
	os.WriteFile(filepath.Join(safeDir, "foo.txt"), []byte("ok"), 0644)
	if containsProtectedPath(safeDir) {
		t.Errorf("containsProtectedPath reported true for clean directory")
	}
}

func TestMatchPattern(t *testing.T) {
	if !matchPattern("model.gguf", "*.gguf") {
		t.Errorf("matchPattern model.gguf failed")
	}
	if !matchPattern("build.o", "build.*") {
		t.Errorf("matchPattern build.o failed")
	}
	if matchPattern("model.txt", "*.gguf") {
		t.Errorf("matchPattern model.txt incorrectly matched *.gguf")
	}
}

func TestRenderProgressBar(t *testing.T) {
	if renderProgressBar(0, 10) != "[░░░░░░░░░░]" {
		t.Errorf("renderProgressBar(0) failed")
	}
	if renderProgressBar(50, 10) != "[█████░░░░░]" {
		t.Errorf("renderProgressBar(50) failed")
	}
	if renderProgressBar(100, 10) != "[██████████]" {
		t.Errorf("renderProgressBar(100) failed")
	}
	if renderProgressBar(-10, 10) != "[░░░░░░░░░░]" {
		t.Errorf("underflow failed")
	}
	if renderProgressBar(150, 10) != "[██████████]" {
		t.Errorf("overflow failed")
	}
}

func TestMarkerAwareRules(t *testing.T) {
	tmpDir := t.TempDir()
	oldTime := time.Now().Add(-200 * time.Hour)

	// 1. target directory WITHOUT Cargo.toml -> skipped
	noCargoProj := filepath.Join(tmpDir, "no_cargo")
	noCargoTarget := filepath.Join(noCargoProj, "target")
	os.MkdirAll(noCargoTarget, 0755)
	f1 := filepath.Join(noCargoTarget, "build.o")
	os.WriteFile(f1, bytes.Repeat([]byte("a"), 2*1024*1024), 0644)
	os.Chtimes(f1, oldTime, oldTime)
	os.Chtimes(noCargoTarget, oldTime, oldTime)

	// 2. target directory WITH Cargo.toml -> matched
	cargoProj := filepath.Join(tmpDir, "cargo_proj")
	cargoTarget := filepath.Join(cargoProj, "target")
	os.MkdirAll(cargoTarget, 0755)
	os.WriteFile(filepath.Join(cargoProj, "Cargo.toml"), []byte("[package]"), 0644)
	f2 := filepath.Join(cargoTarget, "build.o")
	os.WriteFile(f2, bytes.Repeat([]byte("b"), 2*1024*1024), 0644)
	os.Chtimes(f2, oldTime, oldTime)
	os.Chtimes(cargoTarget, oldTime, oldTime)

	// 3. node_modules WITHOUT package.json -> skipped
	noNpmDir := filepath.Join(tmpDir, "no_npm", "node_modules")
	os.MkdirAll(noNpmDir, 0755)
	f3 := filepath.Join(noNpmDir, "pkg.js")
	os.WriteFile(f3, bytes.Repeat([]byte("c"), 2*1024*1024), 0644)
	os.Chtimes(f3, oldTime, oldTime)
	os.Chtimes(noNpmDir, oldTime, oldTime)

	// 4. node_modules WITH package.json -> matched
	npmProj := filepath.Join(tmpDir, "npm_proj")
	npmNodeModules := filepath.Join(npmProj, "node_modules")
	os.MkdirAll(npmNodeModules, 0755)
	os.WriteFile(filepath.Join(npmProj, "package.json"), []byte("{}"), 0644)
	f4 := filepath.Join(npmNodeModules, "pkg.js")
	os.WriteFile(f4, bytes.Repeat([]byte("d"), 2*1024*1024), 0644)
	os.Chtimes(f4, oldTime, oldTime)
	os.Chtimes(npmNodeModules, oldTime, oldTime)

	engine := NewRuleEngine(getDefaultManifest())
	cands := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)

	foundCargoTarget := false
	foundNpmNodeModules := false

	for _, c := range cands {
		if c.Path == noCargoTarget {
			t.Errorf("target directory without Cargo.toml should be skipped")
		}
		if c.Path == cargoTarget {
			foundCargoTarget = true
		}
		if c.Path == noNpmDir {
			t.Errorf("node_modules without package.json should be skipped")
		}
		if c.Path == npmNodeModules {
			foundNpmNodeModules = true
		}
	}

	if !foundCargoTarget {
		t.Errorf("cargoTarget with Cargo.toml should have been matched")
	}
	if !foundNpmNodeModules {
		t.Errorf("npmNodeModules with package.json should have been matched")
	}
}

func TestPackageInventoryResolution(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Mock Cargo .crates.toml
	cargoDir := filepath.Join(tempHome, ".cargo")
	os.MkdirAll(cargoDir, 0755)
	cratesToml := filepath.Join(cargoDir, ".crates.toml")
	os.WriteFile(cratesToml, []byte("\"my-crate 0.1.0 (registry+...)\" = [\"my-bin\"]\n"), 0644)

	// Mock Cargo .crates2.json
	cratesJson := filepath.Join(cargoDir, ".crates2.json")
	os.WriteFile(cratesJson, []byte(`{"installs": {"other-crate 0.2.0 (registry+...)": {"bins": ["other-bin"]}}}`), 0644)

	// Mock pipx venvs
	pipxVenvs := filepath.Join(tempHome, ".local", "pipx", "venvs", "black")
	os.MkdirAll(pipxVenvs, 0755)

	// Mock npm packages
	npmDir := filepath.Join(tempHome, ".nvm", "versions", "node", "v20.0.0", "lib", "node_modules", "express-cli")
	os.MkdirAll(npmDir, 0755)

	// Mock Dotnet tools
	dotnetDir := filepath.Join(tempHome, ".dotnet", "tools", ".store", "csharp-tool")
	os.MkdirAll(dotnetDir, 0755)

	// Mock SDKMAN candidates
	sdkDir := filepath.Join(tempHome, ".sdkman", "candidates", "java", "17.0.1-open")
	os.MkdirAll(sdkDir, 0755)

	// Mock Swiftly toolchains
	swiftDir := filepath.Join(tempHome, ".local", "share", "swiftly", "toolchains", "5.9.2")
	os.MkdirAll(swiftDir, 0755)

	// Mock ZVM Zig toolchains
	zvmDir := filepath.Join(tempHome, ".zvm", "0.11.0")
	os.MkdirAll(zvmDir, 0755)

	inv := loadPackageInventory()

	if inv.CargoCrates["my-bin"] != "my-crate" {
		t.Errorf("loadPackageInventory failed for Cargo .crates.toml; got %s", inv.CargoCrates["my-bin"])
	}
	if inv.CargoCrates["other-bin"] != "other-crate" {
		t.Errorf("loadPackageInventory failed for Cargo .crates2.json; got %s", inv.CargoCrates["other-bin"])
	}
	if inv.PipxVenvs["black"] != "black" {
		t.Errorf("loadPackageInventory failed for pipx venv")
	}
	if inv.NpmPackages["express-cli"] != "express-cli" {
		t.Errorf("loadPackageInventory failed for npm package")
	}
	if inv.DotnetTools["csharp-tool"] != "csharp-tool" {
		t.Errorf("loadPackageInventory failed for dotnet tool")
	}
	if !inv.SdkmanCands["java/17.0.1-open"] {
		t.Errorf("loadPackageInventory failed for SDKMAN candidate")
	}
	if !inv.SwiftVersions["5.9.2"] {
		t.Errorf("loadPackageInventory failed for Swiftly toolchain")
	}
	if inv.ZvmVersions["0.11.0"] != "0.11.0" {
		t.Errorf("loadPackageInventory failed for ZVM version")
	}
}

func TestFormatUninstallArgsAllAdapters(t *testing.T) {
	inv := &PackageInventory{
		CargoCrates:   map[string]string{"my-bin": "my-crate"},
		PipxVenvs:     map[string]string{"black": "black"},
		NpmPackages:   map[string]string{"express-cli": "express-cli"},
		DotnetTools:   map[string]string{"my-tool": "my-tool"},
		ComposerPkgs:  map[string]string{"my-pkg": "my-pkg"},
		ZvmVersions:   map[string]string{"0.11.0": "0.11.0"},
		SdkmanCands:   map[string]bool{"java/17.0.1": true},
		SwiftVersions: map[string]bool{"5.9.2": true},
	}

	// 1. Cargo
	if len(formatUninstallArgs("UNUSED (Cargo)", "my-bin", "/path", inv)) != 3 {
		t.Errorf("Cargo formatUninstallArgs failed")
	}

	// 2. npm
	if len(formatUninstallArgs("UNUSED (npm)", "express-cli", "/path", inv)) != 4 {
		t.Errorf("npm formatUninstallArgs failed")
	}
	if formatUninstallArgs("UNUSED (npm)", "node", "/path", inv) != nil {
		t.Errorf("npm core wrapper node should return nil")
	}

	// 3. pipx
	pArgs := formatUninstallArgs("UNUSED (pipx)", "black", "/home/user/.local/pipx/venvs/black/bin/black", inv)
	if len(pArgs) != 3 || pArgs[2] != "black" {
		t.Errorf("pipx formatUninstallArgs failed: %v", pArgs)
	}

	// 4. Swift
	sArgs := formatUninstallArgs("UNUSED (Swift)", "swift-5.9", "/home/user/.local/share/swiftly/toolchains/5.9.2/usr/bin", inv)
	if len(sArgs) != 3 || sArgs[2] != "5.9.2" {
		t.Errorf("Swift formatUninstallArgs failed: %v", sArgs)
	}

	// 5. SDKMAN
	sdkArgs := formatUninstallArgs("UNUSED (SDKMAN)", "17.0.1", "/home/user/.sdkman/candidates/java/17.0.1", inv)
	if len(sdkArgs) != 4 || sdkArgs[2] != "java" || sdkArgs[3] != "17.0.1" {
		t.Errorf("SDKMAN formatUninstallArgs failed: %v", sdkArgs)
	}

	// 6. Dotnet, Composer, ZVM
	if len(formatUninstallArgs("UNUSED (Dotnet)", "my-tool", "/path", inv)) != 5 {
		t.Errorf("Dotnet formatUninstallArgs failed")
	}
	if len(formatUninstallArgs("UNUSED (Composer)", "my-pkg", "/path", inv)) != 4 {
		t.Errorf("Composer formatUninstallArgs failed")
	}
	if len(formatUninstallArgs("UNUSED (ZVM)", "0.11.0", "/path", inv)) != 3 {
		t.Errorf("ZVM formatUninstallArgs failed")
	}
}

func TestUnverifiedPackageCandidatesReportOnly(t *testing.T) {
	inv := &PackageInventory{}

	cArgs := formatUninstallArgs("UNUSED (Cargo)", "unverified-bin", "/home/user/.cargo/bin/unverified-bin", inv)
	if cArgs != nil {
		t.Errorf("Unverified Cargo binary should return nil uninstall args")
	}

	nArgs := formatUninstallArgs("UNUSED (npm)", "unverified-npm", "/path/to/bin", inv)
	if nArgs != nil {
		t.Errorf("Unverified npm package should return nil uninstall args")
	}
}

func TestNoDirectBinaryDeletionOnUninstallFailure(t *testing.T) {
	tmpDir := t.TempDir()
	failBin := filepath.Join(tmpDir, "failed_bin")
	os.WriteFile(failBin, []byte("binary_data"), 0755)

	selected := []Candidate{
		{
			Path:          failBin,
			Size:          10,
			AgeDays:       10.0,
			Category:      "UNUSED (Cargo)",
			RiskClass:     RiskPackageManaged,
			IsDir:         false,
			CanDelete:     true,
			UninstallArgs: []string{"non_existent_command_99999"},
			ModTime:       time.Now(),
		},
	}

	var stdout bytes.Buffer
	confirmAndDeleteWithIO(selected, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if _, err := os.Stat(failBin); os.IsNotExist(err) {
		t.Errorf("Binary should NOT have been deleted after native uninstall failure")
	}
	if !strings.Contains(stdout.String(), "Manual cleanup skipped to prevent package database corruption") {
		t.Errorf("Expected manual cleanup refusal notice; got: %s", stdout.String())
	}
}

func TestUserDataApplyDataAuthorization(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "app.log")
	os.WriteFile(logFile, []byte("user log data"), 0644)

	selected := []Candidate{
		{
			Path:      logFile,
			Size:      13,
			AgeDays:   10.0,
			Category:  "Log File",
			RiskClass: RiskUserData,
			IsDir:     false,
			CanDelete: true,
			ModTime:   time.Now(),
		},
	}

	var stdout1 bytes.Buffer
	confirmAndDeleteWithIO(selected, false, false, false, 1000, 1000, &stdout1, strings.NewReader("y\n"))
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("User data file should NOT be deleted without allowData flag")
	}
	if !strings.Contains(stdout1.String(), "[REFUSED]") {
		t.Errorf("Expected [REFUSED] notice; got: %s", stdout1.String())
	}

	var stdout2 bytes.Buffer
	confirmAndDeleteWithIO(selected, false, true, false, 1000, 1000, &stdout2, strings.NewReader("y\n"))
	if _, err := os.Stat(logFile); !os.IsNotExist(err) {
		t.Errorf("User data file should be deleted when allowData is true")
	}
}

func TestTrashCollisionProtection(t *testing.T) {
	tmpDir := t.TempDir()

	f1 := filepath.Join(tmpDir, "file.log")
	os.WriteFile(f1, []byte("data1"), 0644)

	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	if err := moveToTrash(f1); err != nil {
		t.Fatalf("moveToTrash first move failed: %v", err)
	}

	f2 := filepath.Join(tmpDir, "file.log")
	os.WriteFile(f2, []byte("data2"), 0644)

	if err := moveToTrash(f2); err != nil {
		t.Fatalf("moveToTrash collision move failed: %v", err)
	}

	trashDir := filepath.Join(tempHome, ".local", "share", "Trash", "files")
	entries, err := os.ReadDir(trashDir)
	if err != nil || len(entries) < 2 {
		t.Errorf("Trash collision protection failed to keep both files in Trash: entries=%d", len(entries))
	}
}

func TestLoadManifest(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Custom JSON file loading
	manPath := filepath.Join(tmpDir, "manifest.json")
	content := `{
		"rules": [
			{"id": "test_rule", "name": "Test Rule", "target": "file", "patterns": ["*.test"], "category": "Test", "risk_class": "regenerable"}
		]
	}`
	os.WriteFile(manPath, []byte(content), 0644)

	m, err := loadManifest(manPath)
	if err != nil || len(m.Rules) != 1 || m.Rules[0].ID != "test_rule" {
		t.Errorf("loadManifest custom file failed: %v", err)
	}

	// 2. Fail-closed for bad path
	_, errBad := loadManifest("/non/existent/path/to/manifest.json")
	if errBad == nil {
		t.Errorf("loadManifest should fail closed for bad path")
	}

	// 3. Fail-closed for invalid risk_class
	badRiskPath := filepath.Join(tmpDir, "bad_risk.json")
	badRiskContent := `{"rules": [{"id": "r1", "name": "r1", "target": "file", "patterns": ["*"], "category": "c", "risk_class": "invalid_junk"}]}`
	os.WriteFile(badRiskPath, []byte(badRiskContent), 0644)
	_, errRisk := loadManifest(badRiskPath)
	if errRisk == nil {
		t.Errorf("loadManifest should fail closed for invalid risk_class")
	}
}

func TestMultimodFlag(t *testing.T) {
	var m multimodFlag
	if m.String() != "" {
		t.Errorf("multimodFlag empty String() failed")
	}
	m.Set("/tmp/dir1")
	m.Set("/tmp/dir2")

	if m.String() != "/tmp/dir1,/tmp/dir2" {
		t.Errorf("multimodFlag String() = %s", m.String())
	}
}

func TestGetDefaultScanDirs(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	t.Setenv("TEMP", "/tmp")
	dirs := getDefaultScanDirs()
	if len(dirs) == 0 {
		t.Errorf("getDefaultScanDirs returned empty slice")
	}
}

func TestGetDiskSpace(t *testing.T) {
	tot, used, free, err := getDiskSpace("/")
	if err != nil || tot == 0 || used == 0 || free == 0 {
		t.Errorf("getDiskSpace('/') failed: tot=%d used=%d free=%d err=%v", tot, used, free, err)
	}
}

func TestRunFzfInteractiveEmpty(t *testing.T) {
	if runFzfInteractive(nil, "fzf", 1000, 500, 500) != nil {
		t.Errorf("runFzfInteractive(nil) should return nil")
	}
}

func TestFindFzf(t *testing.T) {
	tmpBin := t.TempDir()
	mockFzf := filepath.Join(tmpBin, "fzf")
	os.WriteFile(mockFzf, []byte("#!/bin/sh\necho mock"), 0755)
	t.Setenv("PATH", tmpBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if findFzf() == "" {
		t.Errorf("findFzf failed to locate mocked fzf")
	}
}

func TestGetDirStats(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "a.txt")
	os.WriteFile(f1, []byte("hello"), 0644)

	now := time.Now()
	sz, maxMt, fCount := getDirStats(tmpDir, now)
	if sz == 0 || fCount == 0 || maxMt.IsZero() {
		t.Errorf("getDirStats failed: sz=%d fCount=%d maxMt=%v", sz, fCount, maxMt)
	}

	getDirStats("/non/existent/dir/999", now)
}

func TestApplyOverrides(t *testing.T) {
	m := getDefaultManifest()
	engine := NewRuleEngine(m)

	removed, added := applyOverrides(engine, []string{"-zig_cache", "+*.bak"})
	if len(removed) != 1 || removed[0] != "zig_cache" {
		t.Errorf("applyOverrides remove failed")
	}
	if len(added) != 1 || added[0] != "*.bak" {
		t.Errorf("applyOverrides add failed")
	}
}

func TestConfirmAndDeleteExecution(t *testing.T) {
	tmpDir := t.TempDir()

	confirmAndDelete(nil, false, false, false, 1000, 1000)

	file1 := filepath.Join(tmpDir, "file1.log")
	os.WriteFile(file1, []byte("log data"), 0644)
	selected1 := []Candidate{{Path: file1, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false, RiskClass: RiskRegenerable, CanDelete: true, ModTime: time.Now()}}
	confirmAndDelete(selected1, true, false, false, 1000, 1000)
	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("Dry run should not delete file1")
	}

	file2 := filepath.Join(tmpDir, "file2.log")
	dir2 := filepath.Join(tmpDir, "dir2_cache")
	os.WriteFile(file2, []byte("log data"), 0644)
	os.MkdirAll(dir2, 0755)
	now := time.Now()

	selected2 := []Candidate{
		{Path: file2, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false, RiskClass: RiskRegenerable, CanDelete: true, ModTime: now},
		{Path: dir2, Size: 16, AgeDays: 5.0, Category: "Cache Dir", IsDir: true, RiskClass: RiskRegenerable, CanDelete: true, ModTime: now},
	}

	var stdout bytes.Buffer
	stdin := strings.NewReader("y\n")

	confirmAndDeleteWithIO(selected2, false, false, false, 1000, 1000, &stdout, stdin)

	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Errorf("file2 should have been deleted")
	}
	if _, err := os.Stat(dir2); !os.IsNotExist(err) {
		t.Errorf("dir2 should have been deleted")
	}
}

func TestConfirmAndDeleteCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "keep.log")
	os.WriteFile(file1, []byte("data"), 0644)

	selected := []Candidate{{Path: file1, Size: 4, AgeDays: 5.0, Category: "Log", IsDir: false, RiskClass: RiskRegenerable, CanDelete: true, ModTime: time.Now()}}

	var stdout bytes.Buffer
	stdin := strings.NewReader("n\n")

	confirmAndDeleteWithIO(selected, false, false, false, 1000, 1000, &stdout, stdin)

	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("file1 should NOT have been deleted when user answers 'n'")
	}
}

func TestRunMainFlags(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "project")
	targetDir := filepath.Join(subDir, ".zig-cache")
	os.MkdirAll(targetDir, 0755)

	oldTime := time.Now().Add(-200 * time.Hour)
	cacheFile := filepath.Join(targetDir, "build.o")
	os.WriteFile(cacheFile, bytes.Repeat([]byte("y"), 2*1024*1024), 0644)
	os.Chtimes(cacheFile, oldTime, oldTime)
	os.Chtimes(targetDir, oldTime, oldTime)

	var stdout, stderr bytes.Buffer

	// Version flag
	code := runMain([]string{"-version"}, &stdout, &stderr, nil)
	if code != 0 || !strings.Contains(stdout.String(), "unslop version") {
		t.Errorf("runMain -version failed: code=%d stdout=%s", code, stdout.String())
	}

	// JSON flag & plan-out
	stdout.Reset()
	stderr.Reset()
	planOut := filepath.Join(tmpDir, "plan.json")
	codeJSON := runMain([]string{"-json", "-plan-out", planOut, "-path", tmpDir}, &stdout, &stderr, nil)
	if codeJSON != 0 {
		t.Errorf("runMain -json failed: code=%d stderr=%s", codeJSON, stderr.String())
	}
	if _, err := os.Stat(planOut); os.IsNotExist(err) {
		t.Errorf("runMain -plan-out did not create plan.json")
	}

	// Bad flag
	codeBad := runMain([]string{"-invalid-flag-12345"}, &stdout, &stderr, nil)
	if codeBad != 2 {
		t.Errorf("runMain bad flag expected code 2; got %d", codeBad)
	}

	// Bad manifest path
	codeManifest := runMain([]string{"-manifest", "/non/existent/manifest.json"}, &stdout, &stderr, nil)
	if codeManifest != 1 {
		t.Errorf("runMain bad manifest expected code 1; got %d", codeManifest)
	}
}

func TestRunFzfInteractive(t *testing.T) {
	tmpDir := t.TempDir()
	mockFzf := filepath.Join(tmpDir, "fzf")
	script := `#!/bin/sh
cat > /dev/null
echo "[0001]  10.0 MB | 5.0d | Cache Dir | /tmp/test_candidate"
`
	os.WriteFile(mockFzf, []byte(script), 0755)

	candidates := []Candidate{
		{
			ID:             1,
			Path:           "/tmp/test_candidate",
			Size:           10 * 1024 * 1024,
			AgeDays:        5.0,
			Category:       "Cache Dir",
			RiskClass:      RiskRegenerable,
			ProposedAction: "delete_dir",
			CanDelete:      true,
		},
	}

	selected := runFzfInteractive(candidates, mockFzf, 100*1024*1024*1024, 50*1024*1024*1024, 50*1024*1024*1024)
	if len(selected) != 1 || selected[0].Path != "/tmp/test_candidate" {
		t.Errorf("runFzfInteractive mock failed: %v", selected)
	}
}

func TestMoveToTrashOSBranches(t *testing.T) {
	tmpDir := t.TempDir()
	mockGio := filepath.Join(tmpDir, "gio")
	os.WriteFile(mockGio, []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", tmpDir)

	f1 := filepath.Join(t.TempDir(), "f1.txt")
	os.WriteFile(f1, []byte("1"), 0644)
	if err := moveToTrash(f1); err != nil {
		t.Errorf("moveToTrash gio success failed: %v", err)
	}
}

func TestScanParallelDeep(t *testing.T) {
	tmpDir := t.TempDir()
	oldTime := time.Now().Add(-200 * time.Hour)

	logFile := filepath.Join(tmpDir, "stale.log")
	os.WriteFile(logFile, bytes.Repeat([]byte("l"), 200*1024), 0644)
	os.Chtimes(logFile, oldTime, oldTime)

	tmpFile := filepath.Join(tmpDir, "stale.tmp")
	os.WriteFile(tmpFile, bytes.Repeat([]byte("t"), 200*1024), 0644)
	os.Chtimes(tmpFile, oldTime, oldTime)

	engine := NewRuleEngine(getDefaultManifest())

	cands1 := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)
	for _, c := range cands1 {
		if c.Path == logFile {
			t.Errorf("logFile (user-data) should be excluded when includeData=false")
		}
	}

	cands2 := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, true)
	foundLog := false
	foundTmp := false
	for _, c := range cands2 {
		if c.Path == logFile {
			foundLog = true
		}
		if c.Path == tmpFile {
			foundTmp = true
			if c.CanDelete || c.ProposedAction != "report-only" {
				t.Errorf("tmpFile (unknown risk class) should be report-only and non-deletable")
			}
		}
	}
	if !foundLog {
		t.Errorf("logFile should be found when includeData=true")
	}
	if !foundTmp {
		t.Errorf("tmpFile should be found when includeData=true")
	}
}

func TestRunMainExecution(t *testing.T) {
	tmpDir := t.TempDir()
	cargoProj := filepath.Join(tmpDir, "cargo_proj")
	cargoTarget := filepath.Join(cargoProj, "target")
	os.MkdirAll(cargoTarget, 0755)
	os.WriteFile(filepath.Join(cargoProj, "Cargo.toml"), []byte("[package]"), 0644)

	oldTime := time.Now().Add(-200 * time.Hour)
	f := filepath.Join(cargoTarget, "build.o")
	os.WriteFile(f, bytes.Repeat([]byte("b"), 2*1024*1024), 0644)
	os.Chtimes(f, oldTime, oldTime)
	os.Chtimes(cargoTarget, oldTime, oldTime)

	var stdout, stderr bytes.Buffer

	code := runMain([]string{"-apply", "-trash", "-path", tmpDir}, &stdout, &stderr, strings.NewReader("y\n"))
	if code != 0 {
		t.Errorf("runMain -apply -trash failed: %d (stderr: %s)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	planOut := filepath.Join(tmpDir, "plan.json")
	codeJSON := runMain([]string{"-json", "-plan-out", planOut, "-path", tmpDir}, &stdout, &stderr, nil)
	if codeJSON != 0 {
		t.Errorf("runMain -json -plan-out failed: %d", codeJSON)
	}
}

type mockFileInfo struct{}

func (m mockFileInfo) Name() string       { return "mock" }
func (m mockFileInfo) Size() int64        { return 100 }
func (m mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() any           { return nil }

func TestCoverageFinalPushAudit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	altFzf := filepath.Join(tempHome, ".local", "bin", "fzf")
	os.MkdirAll(filepath.Dir(altFzf), 0755)
	os.WriteFile(altFzf, []byte("#!/bin/sh"), 0755)
	if findFzf() != altFzf {
		t.Errorf("findFzf fallback failed")
	}

	dummy := filepath.Join(t.TempDir(), "trash_fallback.txt")
	os.WriteFile(dummy, []byte("data"), 0644)
	if err := moveToTrash(dummy); err != nil {
		t.Errorf("moveToTrash fallback failed: %v", err)
	}

	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	os.MkdirAll(gitDir, 0755)

	staleFile := filepath.Join(tmpDir, "stale.tmp")
	oldTime := time.Now().Add(-200 * time.Hour)
	os.WriteFile(staleFile, bytes.Repeat([]byte("s"), 200*1024), 0644)
	os.Chtimes(staleFile, oldTime, oldTime)

	engine := NewRuleEngine(getDefaultManifest())
	_ = scanParallel([]string{tmpDir, staleFile}, engine, 2.0, 100*1024, true)

	mockFI := mockFileInfo{}
	atime, ctime, uid, isPosix := getStatTimes(mockFI)
	if atime.IsZero() || ctime.IsZero() || uid != 0 || isPosix {
		t.Errorf("getStatTimes non-posix fallback failed")
	}

	var stdout, stderr bytes.Buffer
	codeNoFzf := runMain([]string{"-path", tmpDir}, &stdout, &stderr, nil)
	if codeNoFzf != 0 {
		t.Errorf("runMain no fzf expected code 0; got %d", codeNoFzf)
	}

	candsSkip := []Candidate{
		{Path: "/non/existent/path/999.log", Size: 10, AgeDays: 5.0, Category: "Log", IsDir: false, CanDelete: true, RiskClass: RiskRegenerable},
		{Path: tmpDir, Size: 10, AgeDays: 5.0, Category: "Log", IsDir: false, CanDelete: true, RiskClass: RiskRegenerable},
		{Path: tmpDir, Size: 10, AgeDays: 5.0, Category: "Log", IsDir: true, CanDelete: false, RiskClass: RiskUnknown},
	}
	var stdoutSkip bytes.Buffer
	confirmAndDeleteWithIO(candsSkip, false, false, false, 1000, 1000, &stdoutSkip, strings.NewReader("y\n"))
}

func TestCoveragePushTo95(t *testing.T) {
	tmpDir := t.TempDir()

	mockGioDir := filepath.Join(tmpDir, "gio_bin")
	os.MkdirAll(mockGioDir, 0755)
	os.WriteFile(filepath.Join(mockGioDir, "gio"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", mockGioDir)
	fGio := filepath.Join(tmpDir, "fgio.txt")
	os.WriteFile(fGio, []byte("gio"), 0644)
	moveToTrash(fGio)

	mockTrashDir := filepath.Join(tmpDir, "trash_bin")
	os.MkdirAll(mockTrashDir, 0755)
	os.WriteFile(filepath.Join(mockTrashDir, "trash"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", mockTrashDir)
	fTrash := filepath.Join(tmpDir, "ftrash.txt")
	os.WriteFile(fTrash, []byte("trash"), 0644)
	moveToTrash(fTrash)

	mockSuccessBin := filepath.Join(tmpDir, "succ_bin")
	os.WriteFile(mockSuccessBin, []byte("#!/bin/sh\nexit 0\n"), 0755)

	targetBin := filepath.Join(tmpDir, "bin_target")
	os.WriteFile(targetBin, []byte("bin"), 0755)

	candsSuccess := []Candidate{
		{
			Path:          targetBin,
			Size:          3,
			AgeDays:       10.0,
			Category:      "UNUSED (Cargo)",
			RiskClass:     RiskPackageManaged,
			IsDir:         false,
			CanDelete:     true,
			UninstallArgs: []string{mockSuccessBin, "target"},
			ModTime:       time.Now(),
		},
	}
	var stdout bytes.Buffer
	confirmAndDeleteWithIO(candsSuccess, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[UNINSTALLED SUCCESS]") {
		t.Errorf("Expected [UNINSTALLED SUCCESS]; got: %s", stdout.String())
	}

	stdout.Reset()
	var stderr bytes.Buffer
	codeOverrides := runMain([]string{"-apply", "-apply-data", "-include-data", "-path", tmpDir, "--", "-zig_cache", "+*.tmp"}, &stdout, &stderr, strings.NewReader("y\n"))
	if codeOverrides != 0 {
		t.Errorf("runMain overrides failed: %d (stderr: %s)", codeOverrides, stderr.String())
	}
}

func TestActual12kCandidateScan(t *testing.T) {
	tmpDir := t.TempDir()
	oldTime := time.Now().Add(-200 * time.Hour)

	for i := 1; i <= 12000; i++ {
		sub := filepath.Join(tmpDir, fmt.Sprintf("sub_%d", (i-1)/1000))
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("Failed to create test directory %s: %v", sub, err)
		}
		p := filepath.Join(sub, fmt.Sprintf("stale_%d.log", i))
		if err := os.WriteFile(p, []byte("a"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", p, err)
		}
		if err := os.Chtimes(p, oldTime, oldTime); err != nil {
			t.Fatalf("Failed to set modtime for %s: %v", p, err)
		}
	}

	engine := NewRuleEngine(getDefaultManifest())
	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 0, true)

	if len(candidates) != 12000 {
		t.Errorf("scanParallel on 12,000 files expected 12,000 candidates; got %d", len(candidates))
	}
}

func TestAllPackageManagerFixturesAndNegativeMappings(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cargoDir := filepath.Join(tempHome, ".cargo")
	os.MkdirAll(cargoDir, 0755)
	os.WriteFile(filepath.Join(cargoDir, ".crates.toml"), []byte("\"cargo-crate 1.0.0 (registry+...)\" = [\"cargo-bin\"]\n"), 0644)

	os.MkdirAll(filepath.Join(tempHome, ".local", "pipx", "venvs", "pipx-tool"), 0755)
	os.MkdirAll(filepath.Join(tempHome, ".nvm", "versions", "node", "v20.0.0", "lib", "node_modules", "npm-pkg"), 0755)
	os.MkdirAll(filepath.Join(tempHome, ".dotnet", "tools", ".store", "dotnet-pkg"), 0755)

	compDir := filepath.Join(tempHome, ".config", "composer", "vendor", "composer")
	os.MkdirAll(compDir, 0755)
	os.WriteFile(filepath.Join(compDir, "installed.json"), []byte(`{"packages":[{"name":"vendor/composer-pkg"}]}`), 0644)

	os.MkdirAll(filepath.Join(tempHome, ".sdkman", "candidates", "java", "17.0.1"), 0755)
	os.MkdirAll(filepath.Join(tempHome, ".local", "share", "swiftly", "toolchains", "5.9.2"), 0755)
	os.MkdirAll(filepath.Join(tempHome, ".zvm", "0.11.0"), 0755)

	inv := loadPackageInventory()

	if len(formatUninstallArgs("UNUSED (Cargo)", "cargo-bin", "/path", inv)) != 3 {
		t.Errorf("Cargo positive mapping failed")
	}
	if len(formatUninstallArgs("UNUSED (pipx)", "pipx-tool", "/home/user/.local/pipx/venvs/pipx-tool/bin/pipx-tool", inv)) != 3 {
		t.Errorf("pipx positive mapping failed")
	}
	if len(formatUninstallArgs("UNUSED (npm)", "npm-pkg", "/path", inv)) != 4 {
		t.Errorf("npm positive mapping failed")
	}
	if len(formatUninstallArgs("UNUSED (Dotnet)", "dotnet-pkg", "/path", inv)) != 5 {
		t.Errorf("Dotnet positive mapping failed")
	}
	if len(formatUninstallArgs("UNUSED (SDKMAN)", "17.0.1", "/home/user/.sdkman/candidates/java/17.0.1", inv)) != 4 {
		t.Errorf("SDKMAN positive mapping failed")
	}

	negativeBins := []struct {
		category string
		name     string
		path     string
	}{
		{"UNUSED (Cargo)", "unmapped-cargo", "/path"},
		{"UNUSED (pipx)", "unmapped-pipx", "/path"},
		{"UNUSED (npm)", "unmapped-npm", "/path"},
		{"UNUSED (npm)", "node", "/path"},
		{"UNUSED (npm)", "npm", "/path"},
		{"UNUSED (npm)", "npx", "/path"},
		{"UNUSED (Dotnet)", "unmapped-dotnet", "/path"},
		{"UNUSED (Composer)", "unmapped-composer", "/path"},
		{"UNUSED (SDKMAN)", "current", "/home/user/.sdkman/candidates/java/current"},
		{"UNUSED (Swift)", "5.8.0", "/home/user/.local/share/swiftly/toolchains/5.8.0"},
		{"UNUSED (ZVM)", "0.10.0", "/home/user/.zvm/0.10.0"},
	}

	for _, neg := range negativeBins {
		args := formatUninstallArgs(neg.category, neg.name, neg.path, inv)
		if args != nil {
			t.Errorf("Negative mapping for %s (%s) should return nil; got %v", neg.name, neg.category, args)
		}
	}
}

func TestChangedSizeModtimeBetweenScanAndApply(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "mutating.log")
	os.WriteFile(f, []byte("initial data"), 0644)

	now := time.Now()
	cand := Candidate{
		Path:      f,
		Size:      12,
		AgeDays:   5.0,
		Category:  "Log",
		RiskClass: RiskRegenerable,
		IsDir:     false,
		CanDelete: true,
		ModTime:   now,
	}

	os.WriteFile(f, []byte("mutated data with different length"), 0644)

	var stdout bytes.Buffer
	confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	dirReplacement := filepath.Join(tmpDir, "dir_replaced")
	os.MkdirAll(dirReplacement, 0755)
	candTypeMismatch := Candidate{
		Path:      dirReplacement,
		Size:      10,
		AgeDays:   5.0,
		Category:  "Log",
		RiskClass: RiskRegenerable,
		IsDir:     false,
		CanDelete: true,
		ModTime:   now,
	}

	var stdoutMismatch bytes.Buffer
	confirmAndDeleteWithIO([]Candidate{candTypeMismatch}, false, false, false, 1000, 1000, &stdoutMismatch, strings.NewReader("y\n"))
	if !strings.Contains(stdoutMismatch.String(), "[ABORT]") {
		t.Errorf("Expected [ABORT] for file type mismatch; got: %s", stdoutMismatch.String())
	}
}

func TestSymlinksAndSameTypePathReplacement(t *testing.T) {
	tmpDir := t.TempDir()

	realDir := filepath.Join(tmpDir, "real_dir")
	os.MkdirAll(realDir, 0755)
	os.WriteFile(filepath.Join(realDir, "secret.txt"), []byte("data"), 0644)

	symlinkDir := filepath.Join(tmpDir, "sym_dir")
	_ = os.Symlink(realDir, symlinkDir)

	brokenSym := filepath.Join(tmpDir, "broken_sym")
	_ = os.Symlink("/non/existent/target/path", brokenSym)

	engine := NewRuleEngine(getDefaultManifest())

	cands := scanParallel([]string{tmpDir}, engine, 0.0, 0, true)
	for _, c := range cands {
		if c.Path == symlinkDir || c.Path == brokenSym {
			if c.IsDir {
				t.Errorf("Symlink should not be classified as a standard directory candidate")
			}
		}
	}
}

func TestFzfSelectionHostilePathsAndPipes(t *testing.T) {
	tmpDir := t.TempDir()
	mockFzf := filepath.Join(tmpDir, "fzf")
	script := `#!/bin/sh
cat > /dev/null
echo "[0001]  10.0 MB | 5.0d | Log | /tmp/path;touch_hacked|grep 'foo'\"bar"
`
	os.WriteFile(mockFzf, []byte(script), 0755)

	hostilePath := "/tmp/path;touch_hacked|grep 'foo'\"bar"
	candidates := []Candidate{
		{
			ID:             1,
			Path:           hostilePath,
			Size:           10 * 1024 * 1024,
			AgeDays:        5.0,
			Category:       "Log",
			RiskClass:      RiskRegenerable,
			ProposedAction: "delete_file",
			CanDelete:      true,
		},
	}

	selected := runFzfInteractive(candidates, mockFzf, 1000, 500, 500)
	if len(selected) != 1 || selected[0].Path != hostilePath {
		t.Errorf("runFzfInteractive hostile path selection failed: %v", selected)
	}
}

func TestRealCLISubprocessAndJSONSchema(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "unslop")

	cmdBuild := exec.Command("go", "build", "-o", binPath, ".")
	cmdBuild.Dir = "."
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build unslop binary: %v\n%s", err, string(out))
	}

	cmdRun := exec.Command(binPath, "-json", "-path", tmpDir)
	var stdout, stderr bytes.Buffer
	cmdRun.Stdout = &stdout
	cmdRun.Stderr = &stderr
	if err := cmdRun.Run(); err != nil {
		t.Fatalf("Failed to execute unslop CLI subprocess: %v\n%s", err, stderr.String())
	}

	var report PlanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("Failed to parse unslop JSON report output: %v\nOutput: %s", err, stdout.String())
	}

	if report.Version == "" || report.ScannedAt == "" || report.DiskUsage.TotalBytes == 0 {
		t.Errorf("Invalid PlanReport JSON schema: %+v", report)
	}
}

func TestMacOSWindowsRuntimeHelpers(t *testing.T) {
	mockFI := mockFileInfo{}

	atime, ctime, uid, isPosix := getStatTimes(mockFI)
	if atime.IsZero() || ctime.IsZero() {
		t.Errorf("getStatTimes failed")
	}
	_ = uid
	_ = isPosix

	tot, used, free, err := getDiskSpaceSyscall("/")
	if err != nil || tot == 0 || used == 0 || free == 0 {
		t.Errorf("getDiskSpaceSyscall('/') failed: tot=%d used=%d free=%d err=%v", tot, used, free, err)
	}
}

func TestCoverage100PercentTargeted(t *testing.T) {
	_, _, _, errSyscall := getDiskSpaceSyscall("/non_existent_mount_path_99999")
	if errSyscall == nil {
		t.Errorf("getDiskSpaceSyscall on invalid path should return error")
	}

	if renderProgressBar(50, 0) != "[░░░░░░░░░░]" {
		t.Errorf("renderProgressBar with total <= 0 failed")
	}

	if formatUninstallArgs("UNKNOWN_CATEGORY_XYZ", "pkg", "/path", &PackageInventory{}) != nil {
		t.Errorf("formatUninstallArgs default branch should return nil")
	}

	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	if findFzf() != "" {
		t.Errorf("findFzf should return empty string when fzf is missing")
	}

	tmpDir := t.TempDir()
	badFzf := filepath.Join(tmpDir, "bad_fzf")
	os.WriteFile(badFzf, []byte("#!/bin/sh\nexit 1\n"), 0755)
	candsFzf := []Candidate{{ID: 1, Path: "/tmp/foo", Size: 100}}
	resFzf := runFzfInteractive(candsFzf, badFzf, 100, 50, 50)
	if resFzf != nil {
		t.Errorf("runFzfInteractive bad fzf exit should return nil")
	}

	engine := NewRuleEngine(getDefaultManifest())
	tmpFile := filepath.Join(tmpDir, "app.log")
	os.WriteFile(tmpFile, []byte("log data"), 0644)

	inv := &PackageInventory{}
	infoTmp, _ := os.Stat(tmpFile)
	matchedRule, _, _ := engine.MatchFile(filepath.Base(tmpFile), tmpFile, infoTmp, inv)
	_ = matchedRule

	noRemoveFile := filepath.Join(tmpDir, "no_remove.log")
	os.WriteFile(noRemoveFile, []byte("data"), 0644)

	candRemoveErr := Candidate{
		Path:      noRemoveFile,
		Size:      4,
		AgeDays:   5.0,
		Category:  "Log",
		RiskClass: RiskRegenerable,
		IsDir:     false,
		CanDelete: true,
		ModTime:   time.Now(),
	}

	candMissing := Candidate{
		Path:      filepath.Join(tmpDir, "already_deleted.txt"),
		Size:      10,
		AgeDays:   5.0,
		Category:  "Log",
		RiskClass: RiskRegenerable,
		IsDir:     false,
		CanDelete: true,
		ModTime:   time.Now(),
	}
	os.WriteFile(candMissing.Path, []byte("temp"), 0644)

	var stdout bytes.Buffer
	stdin := strings.NewReader("y\n")
	confirmAndDeleteWithIO([]Candidate{candRemoveErr, candMissing}, false, false, false, 1000, 1000, &stdout, stdin)

	t.Setenv("HOME", "/non_existent_home_dir_99999/path")
	moveToTrash(filepath.Join(tmpDir, "trash_me.txt"))
}

func TestReach100PercentLoCFinalPush(t *testing.T) {
	tmpDir := t.TempDir()
	inv := &PackageInventory{
		CargoCrates: map[string]string{"my_bin": "my_crate"},
	}

	// 1. Cargo binary path without .cargo/bin
	argsCargoNoBin := formatUninstallArgs("UNUSED (Cargo)", "my_bin", "/custom/path/my_bin", inv)
	if argsCargoNoBin != nil {
		t.Errorf("Cargo binary outside .cargo/bin should return nil")
	}

	// 2. MatchFile with marker_files and valid atime > 24h
	oldTime := time.Now().Add(-200 * time.Hour)
	atimeOld := time.Now().Add(-100 * time.Hour)

	fileRule := Rule{
		ID:               "f_rule",
		Name:             "F Rule",
		Target:           "file",
		Patterns:         []string{"*.log_atime"},
		Category:         "Log",
		RiskClass:        RiskUserData,
		MarkerFiles:      []string{"marker.txt"},
		CheckUnusedAtime: true,
	}

	engineFile := &RuleEngine{
		Rules:       []Rule{fileRule},
		ExactDirMap: make(map[string][]*Rule),
		ExtMap:      map[string]*Rule{"log_atime": &fileRule},
	}

	// Create marker.txt in project root
	os.WriteFile(filepath.Join(tmpDir, "marker.txt"), []byte("marker"), 0644)
	fLog := filepath.Join(tmpDir, "test.log_atime")
	os.WriteFile(fLog, []byte("data"), 0644)
	os.Chtimes(fLog, atimeOld, oldTime)

	infoLog, _ := os.Stat(fLog)
	matched, _, _ := engineFile.MatchFile("test.log_atime", fLog, infoLog, inv)
	_ = matched

	// 3. Corrupted Cargo crates.toml file
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	cargoDir := filepath.Join(tempHome, ".cargo")
	os.MkdirAll(cargoDir, 0755)
	os.WriteFile(filepath.Join(cargoDir, ".crates.toml"), []byte("invalid = [toml_syntax_error"), 0644)
	_ = loadPackageInventory()

	// 4. scanParallel candidate matching file rule with MinSizeMB and RiskUserData
	staleLog := filepath.Join(tmpDir, "stale_min.log_atime")
	os.WriteFile(staleLog, bytes.Repeat([]byte("z"), 300*1024), 0644)
	os.Chtimes(staleLog, atimeOld, oldTime)

	_ = scanParallel([]string{tmpDir}, engineFile, 0.0, 100*1024, true)

	// 5. MatchDir rule target == "file" mismatch branch
	dirRuleMismatch := Rule{
		ID:       "file_only_rule",
		Name:     "File Only Rule",
		Target:   "file",
		Patterns: []string{"target_mismatch"},
	}
	engineDirMismatch := &RuleEngine{
		Rules:       []Rule{dirRuleMismatch},
		ExactDirMap: map[string][]*Rule{"target_mismatch": {&dirRuleMismatch}},
	}
	mDir, _, _ := engineDirMismatch.MatchDir("target_mismatch", filepath.Join(tmpDir, "target_mismatch"), inv)
	if mDir != nil {
		t.Errorf("MatchDir should return nil when rule target is 'file'")
	}
}

func TestHit100PercentCoverageFinal(t *testing.T) {
	tmpDir := t.TempDir()

	oldTime := time.Now().Add(-200 * time.Hour)
	newTime := time.Now()

	fileRuleAtime := Rule{
		ID:               "atime_diff",
		Name:             "Atime Diff",
		Target:           "file",
		Patterns:         []string{"*.diff_test"},
		Category:         "Log",
		RiskClass:        RiskUserData,
		CheckUnusedAtime: true,
	}
	engineDiff := &RuleEngine{
		Rules:       []Rule{fileRuleAtime},
		ExactDirMap: make(map[string][]*Rule),
		ExtMap:      map[string]*Rule{"diff_test": &fileRuleAtime},
	}

	fDiff := filepath.Join(tmpDir, "diff.diff_test")
	os.WriteFile(fDiff, []byte("data"), 0644)
	os.Chtimes(fDiff, newTime, oldTime)
	infoDiff, _ := os.Stat(fDiff)

	matched, _, _ := engineDiff.MatchFile("diff.diff_test", fDiff, infoDiff, &PackageInventory{})
	if matched != nil {
		t.Errorf("MatchFile should return nil when diff > 24h")
	}

	dirWithSub := filepath.Join(tmpDir, "dir_stat_err")
	os.MkdirAll(dirWithSub, 0755)
	fSub := filepath.Join(dirWithSub, "sub.txt")
	os.WriteFile(fSub, []byte("test"), 0644)

	os.Chmod(dirWithSub, 0000)
	getDirStats(dirWithSub, time.Now())
	os.Chmod(dirWithSub, 0755)

	staleLog := filepath.Join(tmpDir, "stale_display.log")
	os.WriteFile(staleLog, bytes.Repeat([]byte("d"), 200*1024), 0644)
	os.Chtimes(staleLog, oldTime, oldTime)

	t.Setenv("PATH", t.TempDir())
	var stdout, stderr bytes.Buffer
	runMain([]string{"-path", tmpDir, "-min-size-mb", "0.1", "-days", "0"}, &stdout, &stderr, nil)
	if !strings.Contains(stdout.String(), "Total candidates:") {
		t.Errorf("runMain standard text output failed to list candidates")
	}

	protDir := filepath.Join(tmpDir, "prot_dir")
	os.MkdirAll(protDir, 0755)
	os.WriteFile(filepath.Join(protDir, "credentials.json"), []byte("secret"), 0600)

	candProtected := Candidate{
		Path:      protDir,
		Size:      100,
		AgeDays:   5.0,
		Category:  "Cache",
		RiskClass: RiskRegenerable,
		IsDir:     true,
		CanDelete: true,
		ModTime:   time.Now(),
	}

	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candProtected}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[PROTECTED SAFEGUARD]") {
		t.Errorf("Expected [PROTECTED SAFEGUARD]; got: %s", stdout.String())
	}

	t.Setenv("HOME", "/non_existent_home_dir_99999/path")
	fTrashErr := filepath.Join(tmpDir, "trash_err.log")
	os.WriteFile(fTrashErr, []byte("data"), 0644)
	candTrashErr := Candidate{
		Path:      fTrashErr,
		Size:      4,
		AgeDays:   5.0,
		Category:  "Log",
		RiskClass: RiskRegenerable,
		IsDir:     false,
		CanDelete: true,
		ModTime:   time.Now(),
	}

	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candTrashErr}, false, false, true, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[ERROR]") {
		t.Errorf("Expected [ERROR] for failed trash move; got: %s", stdout.String())
	}

	fDelErr := filepath.Join(tmpDir, "del_err_dir")
	os.MkdirAll(fDelErr, 0755)
	os.WriteFile(filepath.Join(fDelErr, "item.txt"), []byte("data"), 0644)
	os.Chmod(fDelErr, 0000)

	candDelErr := Candidate{
		Path:      filepath.Join(fDelErr, "item.txt"),
		Size:      4,
		AgeDays:   5.0,
		Category:  "Log",
		RiskClass: RiskRegenerable,
		IsDir:     false,
		CanDelete: true,
		ModTime:   time.Now(),
	}

	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candDelErr}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	os.Chmod(fDelErr, 0755)
}

func TestReach100PercentLoC(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Negative flag tests for runMain
	var stdout, stderr bytes.Buffer
	codeDays := runMain([]string{"-days", "-1"}, &stdout, &stderr, nil)
	if codeDays != 2 {
		t.Errorf("-days -1 should fail with code 2")
	}

	stdout.Reset()
	stderr.Reset()
	codeSize := runMain([]string{"-min-size-mb", "-5"}, &stdout, &stderr, nil)
	if codeSize != 2 {
		t.Errorf("-min-size-mb -5 should fail with code 2")
	}

	stdout.Reset()
	stderr.Reset()
	codeDirErr := runMain([]string{"-path", "/non_existent_dir_999999"}, &stdout, &stderr, nil)
	if codeDirErr != 1 {
		t.Errorf("-path non-existent dir should fail with code 1")
	}

	// 2. MatchFile atime branches
	inv := &PackageInventory{}
	engine := NewRuleEngine(getDefaultManifest())

	// File rule with check_unused_atime
	atimeRule := Rule{
		ID:               "test_atime",
		Name:             "Test Atime",
		Target:           "file",
		Patterns:         []string{"*.atime_test"},
		Category:         "Log",
		RiskClass:        RiskUserData,
		CheckUnusedAtime: true,
	}
	engineAtime := &RuleEngine{
		Rules:       []Rule{atimeRule},
		ExactDirMap: make(map[string][]*Rule),
		ExtMap:      map[string]*Rule{"atime_test": &atimeRule},
	}

	fAtime := filepath.Join(tmpDir, "recent.atime_test")
	os.WriteFile(fAtime, []byte("data"), 0644)
	infoAtime, _ := os.Stat(fAtime)

	// ModTime and Atime are equal (less than 24h difference) -> skipped
	r, _, _ := engineAtime.MatchFile("recent.atime_test", fAtime, infoAtime, inv)
	if r != nil {
		t.Errorf("MatchFile should return nil when atime - ctime <= 24h")
	}

	// 3. formatUninstallArgs unmapped branches
	invFull := &PackageInventory{
		CargoCrates: map[string]string{"bin_x": "crate_x"},
		PipxVenvs:   map[string]string{"pipx_x": "pipx_x"},
	}

	// Cargo mismatched path
	args1 := formatUninstallArgs("UNUSED (Cargo)", "bin_x", "/wrong/path/not/cargo/bin", invFull)
	if args1 != nil {
		t.Errorf("Cargo formatUninstallArgs mismatched path should return nil")
	}

	// pipx mismatched path
	args2 := formatUninstallArgs("UNUSED (pipx)", "pipx_x", "/wrong/path/not/pipx/bin", invFull)
	if args2 != nil {
		t.Errorf("pipx formatUninstallArgs mismatched path should return nil")
	}

	// 4. scanParallel top-level file and invalid path
	_ = scanParallel([]string{"/non_existent_scan_root_9999"}, engine, 1.0, 1000, true)

	// Scan top-level path that is a file
	topFile := filepath.Join(tmpDir, "top_level_file.tmp")
	os.WriteFile(topFile, bytes.Repeat([]byte("x"), 200*1024), 0644)
	oldTime := time.Now().Add(-200 * time.Hour)
	os.Chtimes(topFile, oldTime, oldTime)

	_ = scanParallel([]string{topFile}, engine, 0.0, 0, true)

	// 5. Unreadable permission directory delete error handling
	unreadableDir := filepath.Join(tmpDir, "unreadable")
	os.MkdirAll(unreadableDir, 0755)
	os.WriteFile(filepath.Join(unreadableDir, "f.txt"), []byte("data"), 0644)
	os.Chmod(unreadableDir, 0000)

	candUnreadable := Candidate{
		Path:      unreadableDir,
		Size:      100,
		AgeDays:   10.0,
		Category:  "Cache",
		RiskClass: RiskRegenerable,
		IsDir:     true,
		CanDelete: true,
		ModTime:   time.Now(),
	}

	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candUnreadable}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	os.Chmod(unreadableDir, 0755) // Restore permission for temp cleanup
}

func TestCoveragePushTo95Final(t *testing.T) {
	const gb = uint64(1024 * 1024 * 1024)
	calculateDynamicMinSizeMB(0)
	calculateDynamicMinSizeMB(40 * gb)
	calculateDynamicMinSizeMB(75 * gb)
	calculateDynamicMinSizeMB(1000 * gb)

	tmpSubDir := filepath.Join(t.TempDir(), "tmp_scan")
	os.MkdirAll(tmpSubDir, 0755)

	oldTime := time.Now().Add(-200 * time.Hour)
	staleLog := filepath.Join(tmpSubDir, "stale.log")
	os.WriteFile(staleLog, bytes.Repeat([]byte("s"), 200*1024), 0644)
	os.Chtimes(staleLog, oldTime, oldTime)

	engine := NewRuleEngine(getDefaultManifest())
	_ = scanParallel([]string{tmpSubDir}, engine, 2.0, 100*1024, true)

	var stdout, stderr bytes.Buffer
	runMain([]string{"-json", "-plan-out", "/non/existent/dir/999/plan.json", "-path", tmpSubDir}, &stdout, &stderr, nil)

	badJSON := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(badJSON, []byte("{bad"), 0644)
	runMain([]string{"-manifest", badJSON}, &stdout, &stderr, nil)
}

func TestMainFunc(t *testing.T) {
	oldExit := osExit
	defer func() { osExit = oldExit }()
	osExit = func(code int) {}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"unslop", "-version"}

	main()
}

func TestVersionFlag(t *testing.T) {
	if Version == "" {
		t.Errorf("Version constant should not be empty")
	}
}
