package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/config"
)

type cancellingDiagnostic struct{ cancel context.CancelFunc }

func (w cancellingDiagnostic) Write(p []byte) (int, error) {
	w.cancel()
	return len(p), nil
}

func TestScanCancellationAndFutureFileAge(t *testing.T) {
	t.Setenv("PATH", "")
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, err := InspectSubtree(ctx, root, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("subtree continued after cancellation: %v", err)
	}
	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{{ID: "file", Target: "file", Patterns: []string{"*.bin"}, RiskClass: config.RiskRegenerable}}})
	if items, err := ScanLive(ctx, []string{root}, engine, 0, 0, 0, false, io.Discard, nil); !errors.Is(err, context.Canceled) || len(items) != 0 {
		t.Fatalf("scan continued after cancellation: %+v %v", items, err)
	}
	path := filepath.Join(root, "future.bin")
	if err := os.WriteFile(path, []byte("future"), 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(24 * time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	items, err := ScanLive(context.Background(), []string{path}, engine, 0, 0, 0, false, io.Discard, nil)
	if err != nil || len(items) != 1 || items[0].AgeDays != 0 {
		t.Fatalf("future file has invalid age: %+v %v", items, err)
	}
}

func TestScanStopsAfterDiagnosticCancellation(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "container", "a-blocked")
	if err := os.MkdirAll(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(blocked, 0700)
	if err := os.WriteFile(filepath.Join(root, "container", "z-payload"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	items, err := ScanLive(ctx, []string{root}, config.NewRuleEngine(config.Manifest{}), 0, 0, 0, false, cancellingDiagnostic{cancel}, nil)
	if ctx.Err() == nil || err == nil || len(items) != 0 {
		t.Fatalf("diagnostic cancellation ignored: %+v %v", items, err)
	}
}

func TestSubtreeRejectsUnreadableEntryMetadata(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "payload"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0700)
	if _, _, _, protected, err := InspectSubtree(context.Background(), path, time.Now()); err == nil || !protected {
		t.Fatalf("uninspectable subtree accepted: protected=%t err=%v", protected, err)
	}
	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{{ID: "cache", Target: "dir", Patterns: []string{"cache"}, RiskClass: config.RiskRegenerable}}})
	items, err := ScanLive(context.Background(), []string{path}, engine, 0, 0, 0, false, io.Discard, nil)
	if err == nil {
		t.Fatal("scan concealed incomplete metadata")
	}
	for _, item := range items {
		if item.CanDelete {
			t.Fatalf("uninspectable cache is actionable: %+v", item)
		}
	}
}

func TestScanReportsUnreadableDirectories(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	root := t.TempDir()
	restricted := filepath.Join(root, "restricted")
	if err := os.Mkdir(restricted, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(restricted, 0700)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = write
	defer func() { os.Stderr = original }()
	ScanParallel([]string{root}, config.NewRuleEngine(config.Manifest{}), 0, 0, 0, false)
	write.Close()
	output, _ := io.ReadAll(read)
	read.Close()
	if !strings.Contains(string(output), restricted) || !strings.Contains(string(output), "SCAN ERROR") {
		t.Fatalf("missing access warning: %s", output)
	}
}

func TestCheckedScanReportsMissingRootAndUnreadableCache(t *testing.T) {
	t.Setenv("PATH", "")
	engine := config.NewRuleEngine(config.Manifest{Rules: []config.Rule{{ID: "cache", Target: "dir", Patterns: []string{"cache"}, RiskClass: config.RiskRegenerable}}})
	if _, err := ScanParallelChecked([]string{filepath.Join(t.TempDir(), "missing")}, engine, 0, 0, 0, false); err == nil {
		t.Fatal("missing root did not fail")
	}
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		return
	}
	cache := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(cache, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cache, 0700)
	candidates, err := ScanParallelChecked([]string{cache}, engine, 0, 0, 0, false)
	if err == nil {
		t.Fatal("unreadable cache did not fail")
	}
	for _, c := range candidates {
		if c.CanDelete {
			t.Fatal("unreadable candidate actionable")
		}
	}
}

func TestDefaultRootsIncludeUserTemp(t *testing.T) {
	home, tmp := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	for _, p := range GetDefaultScanDirs() {
		if p == tmp {
			return
		}
	}
	t.Fatal("user temp missing from default scan roots")
}

func TestSessionsAreIndividuallyOptIn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", "")
	m, err := config.LoadManifest("")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	paths := []string{".pi/agent/sessions/project/old.jsonl", ".gemini/antigravity-cli/brain/old/transcript.jsonl", ".gemini/antigravity/brain/old/task.md"}
	for _, p := range paths {
		p = filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("history"), 0600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, old, old)
		os.Chtimes(filepath.Dir(p), old, old)
	}
	fresh := filepath.Join(home, ".pi/agent/sessions/project/new.jsonl")
	if err := os.WriteFile(fresh, []byte("active"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, include := range []bool{false, true} {
		candidates := ScanParallel([]string{home}, config.NewRuleEngine(m), 7, 0, 0, include)
		want := 0
		if include {
			want = len(paths)
		}
		if len(candidates) != want {
			t.Fatalf("include=%v got %+v want %d sessions", include, candidates, want)
		}
		for _, c := range candidates {
			if c.RiskClass != config.RiskUserData || !c.CanDelete || c.Path == fresh {
				t.Fatalf("unexpected candidate %+v", c)
			}
		}
	}
}

func TestRecentAntigravitySessionIsNotPartiallyCleaned(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", "")
	m, err := config.LoadManifest("")
	if err != nil {
		t.Fatal(err)
	}
	session := filepath.Join(home, ".gemini/antigravity-cli/brain/recent")
	if err := os.MkdirAll(session, 0700); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(session, "transcript.jsonl")
	if err := os.WriteFile(transcript, []byte(strings.Repeat("X", 6*1024*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	os.Chtimes(transcript, old, old)
	if err := os.WriteFile(filepath.Join(session, "task.md"), []byte("recent activity"), 0600); err != nil {
		t.Fatal(err)
	}
	if candidates := ScanParallel([]string{home}, config.NewRuleEngine(m), 7, 0, 0, true); len(candidates) != 0 {
		t.Fatalf("recent session partially selected: %+v", candidates)
	}
}

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

	foundPaths := make(map[string]bool)
	for _, c := range candidates {
		foundPaths[c.Path] = true
	}

	for _, path := range []string{unityLib, unrealInter, godotCache, turboCache, jupyterCache, elixirBuild, tfCache, haskellWork, dartTool, pixiEnv} {
		if !foundPaths[path] {
			t.Errorf("Expected candidate %s, but none was found during scan of %s", path, tmpDir)
		}
	}
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

func TestIsExecutableBinaryAndDevBinaryHighlight(t *testing.T) {
	tmpDir := t.TempDir()

	exeFile := filepath.Join(tmpDir, "test.exe")
	if err := os.WriteFile(exeFile, []byte("MZdummy"), 0755); err != nil {
		t.Fatalf("Failed to write exe file: %v", err)
	}
	info, err := os.Stat(exeFile)
	if err != nil {
		t.Fatalf("Failed to stat exe file: %v", err)
	}

	if !IsExecutableBinary(exeFile, info) {
		t.Errorf("Expected IsExecutableBinary to return true for test.exe")
	}

	elfFile := filepath.Join(tmpDir, "mybinary")
	if err := os.WriteFile(elfFile, []byte("\x7fELFbin"), 0755); err != nil {
		t.Fatalf("Failed to write elf file: %v", err)
	}
	elfInfo, err := os.Stat(elfFile)
	if err != nil {
		t.Fatalf("Failed to stat elf file: %v", err)
	}

	if !IsExecutableBinary(elfFile, elfInfo) {
		t.Errorf("Expected IsExecutableBinary to return true for ELF binary mybinary")
	}

	scriptFile := filepath.Join(tmpDir, "script.sh")
	if err := os.WriteFile(scriptFile, []byte("#!/bin/bash\necho 123"), 0755); err != nil {
		t.Fatalf("Failed to write script file: %v", err)
	}
	scriptInfo, err := os.Stat(scriptFile)
	if err != nil {
		t.Fatalf("Failed to stat script file: %v", err)
	}

	if IsExecutableBinary(scriptFile, scriptInfo) {
		t.Errorf("Expected IsExecutableBinary to return false for shell script")
	}
}

func TestConcurrentScanDiagnostics(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	root := t.TempDir()
	for index := 0; index < 64; index++ {
		path := filepath.Join(root, fmt.Sprint(index), "restricted")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(path, 0700) })
	}
	release := make(chan struct{})
	diagnostic := gatedDiagnostics{release: release}
	progressSeen := false
	_, err := ScanLive(context.Background(), []string{root}, config.NewRuleEngine(config.Manifest{}), 0, 0, 0, false, &diagnostic, func(progress Progress) {
		if !progress.Done && !progressSeen {
			progressSeen = true
			close(release)
		}
	})
	if err == nil || !progressSeen || strings.Count(diagnostic.String(), "[SCAN ERROR]") != 64 {
		t.Fatalf("concurrent diagnostics lost: %s; error: %v", &diagnostic, err)
	}
}

type gatedDiagnostics struct {
	bytes.Buffer
	release <-chan struct{}
}

func (writer *gatedDiagnostics) Write(data []byte) (int, error) {
	<-writer.release
	return writer.Buffer.Write(data)
}

func ScanParallel(scanDirs []string, engine *config.RuleEngine, minDays float64, maxDays float64, minSizeBytes int64, includeData bool) []Candidate {
	candidates, _ := ScanParallelChecked(scanDirs, engine, minDays, maxDays, minSizeBytes, includeData)
	return candidates
}
