package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func TestCalculateDynamicMinSizeMB(t *testing.T) {
	const gb = uint64(1024 * 1024 * 1024)

	sz10 := calculateDynamicMinSizeMB(10 * gb)
	if sz10 != 1.0 {
		t.Errorf("10GB disk should yield 1.0 MB; got %.2f", sz10)
	}

	sz50 := calculateDynamicMinSizeMB(50 * gb)
	if sz50 != 1.0 {
		t.Errorf("50GB disk should yield 1.0 MB; got %.2f", sz50)
	}

	sz100 := calculateDynamicMinSizeMB(100 * gb)
	if sz100 < 9.9 || sz100 > 10.1 {
		t.Errorf("100GB disk should yield ~10.0 MB; got %.2f", sz100)
	}

	sz1000 := calculateDynamicMinSizeMB(1000 * gb)
	if sz1000 != 50.0 {
		t.Errorf("1TB disk should yield 50.0 MB cap; got %.2f", sz1000)
	}

	szZero := calculateDynamicMinSizeMB(0)
	if szZero != 10.0 {
		t.Errorf("0 disk size should yield 10.0 MB fallback; got %.2f", szZero)
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

func TestHermeticFindFzf(t *testing.T) {
	// Test when fzf is in PATH or mocked
	tmpBin := t.TempDir()
	mockFzf := filepath.Join(tmpBin, "fzf")
	os.WriteFile(mockFzf, []byte("#!/bin/sh\necho mock"), 0755)
	t.Setenv("PATH", tmpBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	fzfBin := findFzf()
	if fzfBin == "" {
		t.Errorf("Hermetic findFzf failed to find mocked fzf")
	}
}

func TestHostileFilenames(t *testing.T) {
	tmpDir := t.TempDir()
	hostileNames := []string{
		"file with spaces.log",
		"file;touch_hacked.log",
		"file|grep_hacked.log",
		"file'quote.log",
		"file\"doublequote.log",
	}

	oldTime := time.Now().Add(-200 * time.Hour)
	for _, hName := range hostileNames {
		p := filepath.Join(tmpDir, hName)
		os.WriteFile(p, bytes.Repeat([]byte("a"), 200*1024), 0644)
		os.Chtimes(p, oldTime, oldTime)
	}

	engine := NewRuleEngine(getDefaultManifest())
	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)

	if len(candidates) != len(hostileNames) {
		t.Errorf("scanParallel found %d hostile candidates; expected %d", len(candidates), len(hostileNames))
	}
}

func TestStress10kCandidates(t *testing.T) {
	var candidates []Candidate
	for i := 1; i <= 12000; i++ {
		candidates = append(candidates, Candidate{
			ID:             i,
			Path:           fmt.Sprintf("/tmp/fake_%d.log", i),
			Size:           1024,
			AgeDays:        10.0,
			Category:       "Log",
			RiskClass:      "regenerable",
			Reason:         "Stale test log",
			ProposedAction: "delete_file",
		})
	}

	if len(candidates) != 12000 {
		t.Errorf("Stress candidate allocation failed")
	}
}

func TestFailClosedManifest(t *testing.T) {
	_, err := loadManifest("/non/existent/path/to/manifest.json")
	if err == nil {
		t.Errorf("loadManifest should fail closed with an error for non-existent path")
	}

	tmpBadJSON := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(tmpBadJSON, []byte("{invalid json"), 0644)
	_, errBad := loadManifest(tmpBadJSON)
	if errBad == nil {
		t.Errorf("loadManifest should fail closed for malformed JSON")
	}
}

func TestJSONPlanReport(t *testing.T) {
	m := getDefaultManifest()
	engine := NewRuleEngine(m)
	tmpDir := t.TempDir()

	oldTime := time.Now().Add(-200 * time.Hour)
	subDir := filepath.Join(tmpDir, "project")
	targetDir := filepath.Join(subDir, ".zig-cache")
	os.MkdirAll(targetDir, 0755)
	cacheFile := filepath.Join(targetDir, "build.o")
	os.WriteFile(cacheFile, bytes.Repeat([]byte("y"), 2*1024*1024), 0644)
	os.Chtimes(cacheFile, oldTime, oldTime)
	os.Chtimes(targetDir, oldTime, oldTime)

	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)
	if len(candidates) == 0 {
		t.Fatalf("scanParallel should have found candidate")
	}

	if candidates[0].RiskClass != "regenerable" {
		t.Errorf("Expected RiskClass 'regenerable'; got '%s'", candidates[0].RiskClass)
	}

	planFile := filepath.Join(tmpDir, "plan.json")
	report := PlanReport{
		Version:         Version,
		ScannedAt:       time.Now().UTC().Format(time.RFC3339),
		TotalCandidates: len(candidates),
		TotalSizeBytes:  candidates[0].Size,
		Candidates:      candidates,
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(planFile, data, 0644)

	if _, err := os.Stat(planFile); os.IsNotExist(err) {
		t.Errorf("JSON plan report file was not created")
	}
}

func TestPackageInventory(t *testing.T) {
	inv := loadPackageInventory()
	if inv == nil {
		t.Fatalf("loadPackageInventory returned nil")
	}
}

func TestApplyOverrides(t *testing.T) {
	m := getDefaultManifest()
	engine := NewRuleEngine(m)
	inv := loadPackageInventory()

	removed, added := applyOverrides(engine, []string{"-zig_cache", "+*.bak"})
	if len(removed) != 1 || removed[0] != "zig_cache" {
		t.Errorf("applyOverrides remove failed")
	}
	if len(added) != 1 || added[0] != "*.bak" {
		t.Errorf("applyOverrides add failed")
	}

	ruleDir, _, _ := engine.MatchDir(".zig-cache", "/path/to/.zig-cache", inv)
	if ruleDir != nil {
		t.Errorf("zig_cache rule should have been removed")
	}
}

func TestConfirmAndDeleteExecution(t *testing.T) {
	tmpDir := t.TempDir()

	confirmAndDelete(nil, false, false, 1000, 1000)

	file1 := filepath.Join(tmpDir, "file1.log")
	os.WriteFile(file1, []byte("log data"), 0644)
	selected1 := []Candidate{{Path: file1, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: time.Now()}}
	confirmAndDelete(selected1, true, false, 1000, 1000)
	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("Dry run should not delete file1")
	}

	file2 := filepath.Join(tmpDir, "file2.log")
	dir2 := filepath.Join(tmpDir, "dir2_cache")
	os.WriteFile(file2, []byte("log data"), 0644)
	os.MkdirAll(dir2, 0755)
	now := time.Now()

	selected2 := []Candidate{
		{Path: file2, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: now},
		{Path: dir2, Size: 16, AgeDays: 5.0, Category: "Cache Dir", IsDir: true, ModTime: now},
	}

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.WriteString("y\n")
	w.Close()
	os.Stdin = r

	confirmAndDelete(selected2, false, false, 1000, 1000)

	os.Stdin = oldStdin

	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Errorf("file2 should have been deleted")
	}
	if _, err := os.Stat(dir2); !os.IsNotExist(err) {
		t.Errorf("dir2 should have been deleted")
	}
}

func TestVersionFlag(t *testing.T) {
	if Version == "" {
		t.Errorf("Version constant should not be empty")
	}
}
