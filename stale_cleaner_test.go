package main

import (
	"bytes"
	"flag"
	"io"
	"os"
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
		t.Errorf("config.toml should be protected")
	}
	if !isProtected("/path/to/settings.json") {
		t.Errorf("settings.json should be protected")
	}
	if !isProtected("/path/to/rules") {
		t.Errorf("rules should be protected")
	}
	if isProtected("/path/to/random.txt") {
		t.Errorf("random.txt should not be protected")
	}
}

func TestMatchPattern(t *testing.T) {
	if !matchPattern("file.json", "*.json") {
		t.Errorf("file.json should match *.json")
	}
	if !matchPattern("test-dir", "test*") {
		t.Errorf("test-dir should match test*")
	}
	if !matchPattern("/path/to/target/build", "target") {
		t.Errorf("path should match substring target")
	}
}

func TestRenderProgressBar(t *testing.T) {
	bar0 := renderProgressBar(0, 10)
	if bar0 != "[░░░░░░░░░░]" {
		t.Errorf("renderProgressBar(0) = %s", bar0)
	}
	bar50 := renderProgressBar(50, 10)
	if bar50 != "[█████░░░░░]" {
		t.Errorf("renderProgressBar(50) = %s", bar50)
	}
	bar100 := renderProgressBar(100, 10)
	if bar100 != "[██████████]" {
		t.Errorf("renderProgressBar(100) = %s", bar100)
	}
}

func TestFormatUninstallCmd(t *testing.T) {
	cmd1 := formatUninstallCmd("cargo uninstall {name}", "my-pkg", "/path/to/my-pkg")
	if cmd1 != "cargo uninstall my-pkg" {
		t.Errorf("formatUninstallCmd cargo failed: %s", cmd1)
	}

	cmd2 := formatUninstallCmd("sdk uninstall {candidate} {version}", "v1.0", "/path/to/.sdkman/candidates/java/v1.0")
	if cmd2 != "sdk uninstall java v1.0" {
		t.Errorf("formatUninstallCmd sdkman failed: %s", cmd2)
	}
}

func TestRuleEngineMatching(t *testing.T) {
	m := getDefaultManifest()
	engine := NewRuleEngine(m)

	// Test MatchDir
	ruleDir, name, _ := engine.MatchDir(".zig-cache", "/path/to/.zig-cache")
	if ruleDir == nil || ruleDir.Category != "Cache Dir" {
		t.Errorf("MatchDir .zig-cache failed")
	}
	if name != ".zig-cache" {
		t.Errorf("MatchDir name returned %s", name)
	}

	// Test MatchFile for LLM model
	tmpFile := filepath.Join(t.TempDir(), "model.gguf")
	os.WriteFile(tmpFile, []byte("data"), 0644)
	fi, _ := os.Stat(tmpFile)

	ruleFile, _, _ := engine.MatchFile("model.gguf", tmpFile, fi)
	if ruleFile == nil || ruleFile.Category != "LLM Model" {
		t.Errorf("MatchFile model.gguf failed")
	}
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

	// Check if zig_cache rule was removed
	ruleDir, _, _ := engine.MatchDir(".zig-cache", "/path/to/.zig-cache")
	if ruleDir != nil {
		t.Errorf("zig_cache rule should have been removed")
	}
}

func TestLoadManifest(t *testing.T) {
	tmpDir := t.TempDir()
	manPath := filepath.Join(tmpDir, "manifest.json")
	content := `{
		"rules": [
			{"id": "test_rule", "name": "Test Rule", "target": "file", "patterns": ["*.test"], "category": "Test"}
		]
	}`
	os.WriteFile(manPath, []byte(content), 0644)

	m := loadManifest(manPath)
	if len(m.Rules) != 1 || m.Rules[0].ID != "test_rule" {
		t.Errorf("loadManifest custom file failed")
	}

	// Test default fallback for non-existent path
	mDefault := loadManifest("/non/existent/path.json")
	if len(mDefault.Rules) == 0 {
		t.Errorf("loadManifest fallback failed")
	}

	// Test ~/.stale-cleaner.json resolution
	tempHome := t.TempDir()
	dotPath := filepath.Join(tempHome, ".stale-cleaner.json")
	os.WriteFile(dotPath, []byte(content), 0644)
	t.Setenv("HOME", tempHome)

	mDot := loadManifest("")
	if len(mDot.Rules) != 1 || mDot.Rules[0].ID != "test_rule" {
		t.Errorf("loadManifest ~/.stale-cleaner.json failed")
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

func TestFindFzf(t *testing.T) {
	fzfBin := findFzf()
	if fzfBin == "" {
		t.Errorf("findFzf failed to locate fzf binary")
	}
}

func TestPrecountAndScanParallel(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "project")
	os.MkdirAll(subDir, 0755)

	oldTime := time.Now().Add(-100 * time.Hour)

	// Old stale JSON dump file (>5MB to trigger json_artifacts min_size)
	staleFile := filepath.Join(subDir, "dump.json")
	os.WriteFile(staleFile, bytes.Repeat([]byte("x"), 6*1024*1024), 0644)
	os.Chtimes(staleFile, oldTime, oldTime)

	// Old cache dir (>1MB total size)
	cacheDir := filepath.Join(subDir, ".zig-cache")
	os.MkdirAll(cacheDir, 0755)
	cacheFile := filepath.Join(cacheDir, "build.o")
	os.WriteFile(cacheFile, bytes.Repeat([]byte("y"), 2*1024*1024), 0644)
	os.Chtimes(cacheDir, oldTime, oldTime)
	os.Chtimes(cacheFile, oldTime, oldTime)

	count := precountFiles([]string{tmpDir})
	if count < 2 {
		t.Errorf("precountFiles = %d; expected >= 2", count)
	}

	engine := NewRuleEngine(getDefaultManifest())
	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 1*1024*1024)

	if len(candidates) < 2 {
		t.Errorf("scanParallel found %d candidates; expected >= 2", len(candidates))
	}
}

func TestConfirmAndDeleteExecution(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Empty selection test
	confirmAndDelete(nil, false, 1000, 1000)

	// 2. Dry run test
	file1 := filepath.Join(tmpDir, "file1.log")
	os.WriteFile(file1, []byte("log data"), 0644)
	selected1 := []Candidate{{Path: file1, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false}}
	confirmAndDelete(selected1, true, 1000, 1000)
	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("Dry run should not delete file1")
	}

	// 3. User confirmation 'y' deletion test
	file2 := filepath.Join(tmpDir, "file2.log")
	dir2 := filepath.Join(tmpDir, "dir2_cache")
	os.WriteFile(file2, []byte("log data"), 0644)
	os.MkdirAll(dir2, 0755)

	selected2 := []Candidate{
		{Path: file2, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false},
		{Path: dir2, Size: 16, AgeDays: 5.0, Category: "Cache Dir", IsDir: true},
	}

	// Mock stdin with 'y\n'
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.WriteString("y\n")
	w.Close()
	os.Stdin = r

	confirmAndDelete(selected2, false, 1000, 1000)

	os.Stdin = oldStdin

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

	selected := []Candidate{{Path: file1, Size: 4, AgeDays: 5.0, Category: "Log", IsDir: false}}

	// Mock stdin with 'n\n'
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.WriteString("n\n")
	w.Close()
	os.Stdin = r

	confirmAndDelete(selected, false, 1000, 1000)

	os.Stdin = oldStdin

	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("file1 should NOT have been deleted when user answers 'n'")
	}
}

func TestUninstallCmdExecution(t *testing.T) {
	tmpDir := t.TempDir()
	binaryFile := filepath.Join(tmpDir, "dummy_bin")
	os.WriteFile(binaryFile, []byte("bin"), 0755)

	selected := []Candidate{
		{
			Path:         binaryFile,
			Size:         3,
			AgeDays:      10.0,
			Category:     "UNUSED (Cargo)",
			IsDir:        false,
			PackageName:  "dummy_bin",
			UninstallCmd: "non_existent_command_12345",
		},
	}

	// Mock stdin with 'y\ny\n' for initial deletion prompt and fallback prompt
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.WriteString("y\ny\n")
	w.Close()
	os.Stdin = r

	confirmAndDelete(selected, false, 1000, 1000)

	os.Stdin = oldStdin

	if _, err := os.Stat(binaryFile); !os.IsNotExist(err) {
		t.Errorf("Fallback direct removal should have deleted binaryFile")
	}
}

func TestRunFzfInteractiveEmpty(t *testing.T) {
	res := runFzfInteractive(nil, "fzf", 100, 50, 50)
	if res != nil {
		t.Errorf("runFzfInteractive with empty candidates should return nil")
	}
}

func TestGetDirStats(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "a.txt")
	os.WriteFile(f1, []byte("hello"), 0644)

	now := time.Now()
	sz, maxMt, fCount := getDirStats(tmpDir, now)
	if sz != 5 || fCount != 1 || maxMt.IsZero() {
		t.Errorf("getDirStats failed: sz=%d fCount=%d maxMt=%v", sz, fCount, maxMt)
	}
}

func TestFlagUsageOutput(t *testing.T) {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	flag.Usage()

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "stale-cleaner") {
		t.Errorf("flag.Usage output missing header")
	}
}
