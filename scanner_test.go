package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScannerActual12kCandidateScan(t *testing.T) {
	tmpDir := t.TempDir()

	rule := Rule{
		ID:        "actual_12k_rule",
		Name:      "12k Target",
		Target:    "file",
		Patterns:  []string{"cand_*.bin"},
		Category:  "Cache Dir",
		RiskClass: RiskRegenerable,
		MinSizeMB: 0.0,
	}

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	content := []byte("X") // 1 Byte -> 12 KB total footprint across 12,000 files

	// Create 12,000 candidates across subdirectories
	const totalFiles = 12000
	const filesPerSubdir = 1000

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

	engine := NewRuleEngine(Manifest{Rules: []Rule{rule}})

	// Perform parallel scan
	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 0, true)

	if len(candidates) != totalFiles {
		t.Fatalf("Expected exactly %d candidates from scanner; got %d", totalFiles, len(candidates))
	}
}

func TestScanParallelCandidatePruningByAgeAndSize(t *testing.T) {
	tmpDir := t.TempDir()

	rule := Rule{
		ID:        "prune_rule",
		Name:      "Prune Target",
		Target:    "dir",
		Patterns:  []string{"cache_*"},
		Category:  "Cache Dir",
		RiskClass: RiskRegenerable,
		MinSizeMB: 1.0, // Requires 1 MB minimum
	}

	// 1. Candidate directory too small (< 1 MB)
	smallDir := filepath.Join(tmpDir, "cache_small")
	os.MkdirAll(smallDir, 0755)
	os.WriteFile(filepath.Join(smallDir, "data.bin"), []byte("small"), 0644)
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(smallDir, oldTime, oldTime)

	// 2. Candidate directory too young (created now, < 5.0 days)
	youngDir := filepath.Join(tmpDir, "cache_young")
	os.MkdirAll(youngDir, 0755)
	os.WriteFile(filepath.Join(youngDir, "large.bin"), []byte(strings.Repeat("Y", 2*1024*1024)), 0644)

	// 3. Valid candidate directory (old and large)
	validDir := filepath.Join(tmpDir, "cache_valid")
	os.MkdirAll(validDir, 0755)
	validFile := filepath.Join(validDir, "large.bin")
	os.WriteFile(validFile, []byte(strings.Repeat("V", 2*1024*1024)), 0644)
	os.Chtimes(validDir, oldTime, oldTime)
	os.Chtimes(validFile, oldTime, oldTime)

	engine := NewRuleEngine(Manifest{Rules: []Rule{rule}})
	candidates := scanParallel([]string{tmpDir}, engine, 5.0, 100*1024, true)

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

	rule := Rule{
		ID:        "zig_cache",
		Name:      "Zig Cache",
		Target:    "dir",
		Patterns:  []string{".zig-cache"},
		Category:  "Build Cache",
		RiskClass: RiskRegenerable,
	}

	engine := NewRuleEngine(Manifest{Rules: []Rule{rule}})
	candidates := scanParallel([]string{zigCache}, engine, 2.0, 100*1024, true)

	if len(candidates) != 1 {
		t.Fatalf("Expected 1 candidate when scanning explicit candidate root; got %d", len(candidates))
	}
	if candidates[0].Path != zigCache {
		t.Errorf("Expected candidate path to be %s; got %s", zigCache, candidates[0].Path)
	}
}

func TestGlobPatternMatching(t *testing.T) {
	if !matchPattern("app.log", "*.log") {
		t.Errorf("matchPattern *.log failed for app.log")
	}
	if matchPattern("app.txt", "*.log") {
		t.Errorf("matchPattern *.log matched app.txt unexpectedly")
	}
	if !matchPattern("cache-v1", "cache-*") {
		t.Errorf("matchPattern cache-* failed for cache-v1")
	}
}
