package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/config"
)

func TestScannerActual12kCandidateScan(t *testing.T) {
	tmpDir := t.TempDir()

	rule := config.Rule{
		ID:        "actual_12k_rule",
		Name:      "12k Target",
		Target:    "file",
		Patterns:  []string{"cand_*.bin"},
		Category:  "Cache Dir",
		RiskClass: config.RiskRegenerable,
		MinSizeMB: 0.0,
	}

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	content := []byte("X")

	const totalFiles = 1000
	const filesPerSubdir = 200

	for i := 0; i < totalFiles; i += filesPerSubdir {
		sub := filepath.Join(tmpDir, fmt.Sprintf("dir_%d", i))
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("Failed to create subdir: %v", err)
		}
		for j := 0; j < filesPerSubdir; j++ {
			fn := filepath.Join(sub, fmt.Sprintf("cand_%d.bin", i+j))
			if err := os.WriteFile(fn, content, 0644); err != nil {
				t.Fatalf("Failed to write candidate file %s: %v", fn, err)
			}
			if err := os.Chtimes(fn, oldTime, oldTime); err != nil {
				t.Fatalf("Failed to set chtimes: %v", err)
			}
		}
	}

	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{rule}})
	candidates := ScanParallel([]string{tmpDir}, engine, 2.0, 0, 0, true)

	if len(candidates) != totalFiles {
		t.Fatalf("Expected exactly %d candidates from scanner; got %d", totalFiles, len(candidates))
	}
}

func TestScanParallelCandidatePruningByAgeAndSize(t *testing.T) {
	tmpDir := t.TempDir()

	rule := config.Rule{
		ID:        "prune_rule",
		Name:      "Prune Target",
		Target:    "dir",
		Patterns:  []string{"cache_*"},
		Category:  "Cache Dir",
		RiskClass: config.RiskRegenerable,
		MinSizeMB: 1.0,
	}

	smallDir := filepath.Join(tmpDir, "cache_small")
	os.MkdirAll(smallDir, 0755)
	os.WriteFile(filepath.Join(smallDir, "data.bin"), []byte("small"), 0644)
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(smallDir, oldTime, oldTime)

	youngDir := filepath.Join(tmpDir, "cache_young")
	os.MkdirAll(youngDir, 0755)
	os.WriteFile(filepath.Join(youngDir, "large.bin"), []byte(strings.Repeat("Y", 2*1024*1024)), 0644)

	validDir := filepath.Join(tmpDir, "cache_valid")
	os.MkdirAll(validDir, 0755)
	validFile := filepath.Join(validDir, "large.bin")
	os.WriteFile(validFile, []byte(strings.Repeat("V", 2*1024*1024)), 0644)
	os.Chtimes(validDir, oldTime, oldTime)
	os.Chtimes(validFile, oldTime, oldTime)

	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{rule}})
	candidates := ScanParallel([]string{tmpDir}, engine, 5.0, 0, 100*1024, true)

	if len(candidates) != 1 {
		t.Fatalf("Expected exactly 1 candidate after pruning small/young dirs; got %d", len(candidates))
	}
	if candidates[0].Path != validDir {
		t.Errorf("Expected valid candidate path %s; got %s", validDir, candidates[0].Path)
	}
}

func TestScannerRequestedScanRoot(t *testing.T) {
	tmpDir := t.TempDir()
	zigCache := filepath.Join(tmpDir, ".zig-cache")
	os.MkdirAll(zigCache, 0755)

	cacheFile := filepath.Join(zigCache, "cache.bin")
	os.WriteFile(cacheFile, []byte(strings.Repeat("Z", 120*1024)), 0644)

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(zigCache, oldTime, oldTime)
	os.Chtimes(cacheFile, oldTime, oldTime)

	rule := config.Rule{
		ID:        "zig_cache",
		Name:      "Zig Cache",
		Target:    "dir",
		Patterns:  []string{".zig-cache"},
		Category:  "Build Cache",
		RiskClass: config.RiskRegenerable,
	}

	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{rule}})
	candidates := ScanParallel([]string{zigCache}, engine, 2.0, 0, 100*1024, true)

	if len(candidates) != 1 {
		t.Fatalf("Expected 1 candidate when scanning explicit candidate root; got %d", len(candidates))
	}
	if candidates[0].Path != zigCache {
		t.Errorf("Expected candidate path to be %s; got %s", zigCache, candidates[0].Path)
	}
}

func TestEcosystemManifestRules(t *testing.T) {
	manifest, errLoad := config.LoadManifest("")
	if errLoad != nil {
		t.Fatalf("Failed to load embedded default manifest: %v", errLoad)
	}

	engine := config.NewRuleEngine(manifest)
	tmpDir := t.TempDir()

	oldTime := time.Now().Add(-10 * 24 * time.Hour)

	createTestTarget := func(parent, name string, markerFile string) string {
		dir := filepath.Join(parent, name)
		os.MkdirAll(dir, 0755)
		fn := filepath.Join(dir, "cache_data.bin")
		os.WriteFile(fn, []byte("DATA_12345"), 0644)
		os.Chtimes(dir, oldTime, oldTime)
		os.Chtimes(fn, oldTime, oldTime)

		if markerFile != "" {
			mk := filepath.Join(parent, markerFile)
			os.MkdirAll(filepath.Dir(mk), 0755)
			os.WriteFile(mk, []byte("MARKER"), 0644)
		}
		return dir
	}

	unityProj := filepath.Join(tmpDir, "unity_project")
	unityLib := createTestTarget(unityProj, "Library", "Assets/test.cs")

	unrealProj := filepath.Join(tmpDir, "unreal_project")
	unrealInter := createTestTarget(unrealProj, "Intermediate", "Config/DefaultEngine.ini")

	godotProj := filepath.Join(tmpDir, "godot_project")
	godotCache := createTestTarget(godotProj, ".godot", "project.godot")

	turboProj := filepath.Join(tmpDir, "turbo_project")
	turboCache := createTestTarget(turboProj, ".turbo", "")

	jupyterProj := filepath.Join(tmpDir, "jupyter_project")
	jupyterCache := createTestTarget(jupyterProj, ".ipynb_checkpoints", "")

	elixirProj := filepath.Join(tmpDir, "elixir_project")
	elixirBuild := createTestTarget(elixirProj, "_build", "mix.exs")

	tfProj := filepath.Join(tmpDir, "tf_project")
	tfCache := createTestTarget(tfProj, ".terraform", "")

	haskellProj := filepath.Join(tmpDir, "haskell_project")
	haskellWork := createTestTarget(haskellProj, ".stack-work", "")

	dartProj := filepath.Join(tmpDir, "dart_project")
	dartTool := createTestTarget(dartProj, ".dart_tool", "")

	pixiProj := filepath.Join(tmpDir, "pixi_project")
	pixiEnv := createTestTarget(pixiProj, ".pixi", "")

	candidates := ScanParallel([]string{tmpDir}, engine, 2.0, 0, 0, true)

	foundRules := make(map[string]bool)
	for _, c := range candidates {
		foundRules[c.RuleID] = true
	}

	expectedRuleIDs := []string{
		"unity_build",
		"unreal_build",
		"godot_cache",
		"turbo_cache",
		"jupyter_checkpoints",
		"elixir_build",
		"terraform_cache",
		"haskell_build",
		"dart_build",
		"pixi_env",
	}

	for _, ruleID := range expectedRuleIDs {
		if !foundRules[ruleID] {
			t.Errorf("Expected candidate for rule '%s', but none was found during scan of %s", ruleID, tmpDir)
		}
	}

	_ = unityLib
	_ = unrealInter
	_ = godotCache
	_ = turboCache
	_ = jupyterCache
	_ = elixirBuild
	_ = tfCache
	_ = haskellWork
	_ = dartTool
	_ = pixiEnv
}

func TestGitIgnoredTaggingInScanner(t *testing.T) {
	tmpDir := t.TempDir()
	projDir := filepath.Join(tmpDir, "sample_project")
	os.MkdirAll(projDir, 0755)

	giPath := filepath.Join(projDir, ".gitignore")
	os.WriteFile(giPath, []byte("node_modules\ntarget\n"), 0644)

	nodeDir := filepath.Join(projDir, "node_modules")
	os.MkdirAll(nodeDir, 0755)
	fn := filepath.Join(nodeDir, "package.json")
	os.WriteFile(fn, []byte("{}"), 0644)

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(nodeDir, oldTime, oldTime)
	os.Chtimes(fn, oldTime, oldTime)

	rule := config.Rule{
		ID:        "node_modules",
		Name:      "Node Modules",
		Target:    "dir",
		Patterns:  []string{"node_modules"},
		Category:  "Dependencies",
		RiskClass: config.RiskRegenerable,
	}

	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{rule}})
	candidates := ScanParallel([]string{tmpDir}, engine, 2.0, 0, 0, true)

	if len(candidates) != 1 {
		t.Fatalf("Expected 1 candidate for node_modules; got %d", len(candidates))
	}

	if !candidates[0].IsGitIgnored {
		t.Errorf("Expected candidate %s to be tagged as IsGitIgnored=true due to .gitignore entry", candidates[0].Path)
	}
}

func TestScanParallelMaxDaysAgeFiltering(t *testing.T) {
	tmpDir := t.TempDir()

	rule := config.Rule{
		ID:        "cache_rule",
		Name:      "Cache Target",
		Target:    "dir",
		Patterns:  []string{"cache_*"},
		Category:  "Cache Dir",
		RiskClass: config.RiskRegenerable,
	}

	now := time.Now()

	dir10 := filepath.Join(tmpDir, "cache_10d")
	os.MkdirAll(dir10, 0755)
	fn10 := filepath.Join(dir10, "data.bin")
	os.WriteFile(fn10, []byte("10D"), 0644)
	t10 := now.Add(-10 * 24 * time.Hour)
	os.Chtimes(dir10, t10, t10)
	os.Chtimes(fn10, t10, t10)

	dir50 := filepath.Join(tmpDir, "cache_50d")
	os.MkdirAll(dir50, 0755)
	fn50 := filepath.Join(dir50, "data.bin")
	os.WriteFile(fn50, []byte("50D"), 0644)
	t50 := now.Add(-50 * 24 * time.Hour)
	os.Chtimes(dir50, t50, t50)
	os.Chtimes(fn50, t50, t50)

	dir120 := filepath.Join(tmpDir, "cache_120d")
	os.MkdirAll(dir120, 0755)
	fn120 := filepath.Join(dir120, "data.bin")
	os.WriteFile(fn120, []byte("120D"), 0644)
	t120 := now.Add(-120 * 24 * time.Hour)
	os.Chtimes(dir120, t120, t120)
	os.Chtimes(fn120, t120, t120)

	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{rule}})

	candUnlimited := ScanParallel([]string{tmpDir}, engine, 14.0, 0, 0, true)
	if len(candUnlimited) != 2 {
		t.Fatalf("Expected 2 candidates (50d and 120d) with maxDays=0; got %d", len(candUnlimited))
	}

	candBracket := ScanParallel([]string{tmpDir}, engine, 14.0, 90.0, 0, true)
	if len(candBracket) != 1 {
		t.Fatalf("Expected 1 candidate (50d only) with minDays=14 maxDays=90; got %d", len(candBracket))
	}

	if candBracket[0].Path != dir50 {
		t.Errorf("Expected bracket candidate to be %s; got %s", dir50, candBracket[0].Path)
	}
}
