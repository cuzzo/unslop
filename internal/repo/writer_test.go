package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterAndInstructions(t *testing.T) {
	dir, err := os.MkdirTemp("", "unslop-writer-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)

	candidates := []HistoryCandidate{
		{ID: 1, Path: "app.pdb", Size: 1024, Category: "Debug Binary"},
		{ID: 2, Path: "node_modules/", Size: 2048, Category: "Dependency Dump"},
	}

	manifestPath := filepath.Join(dir, "sub", "unslop-git-filter.txt")
	err = WriteFilterManifest(candidates, manifestPath)
	if err != nil {
		t.Fatalf("WriteFilterManifest failed: %v", err)
	}

	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	strContent := string(content)
	if !strings.Contains(strContent, "app.pdb") || !strings.Contains(strContent, "node_modules/") {
		t.Errorf("Manifest missing expected paths. Got:\n%s", strContent)
	}

	// Test default output path fallback
	err = WriteFilterManifest(candidates, "")
	if err != nil {
		t.Fatalf("WriteFilterManifest with empty path failed: %v", err)
	}
	os.Remove("unslop-git-filter.txt")

	instructions := FormatInstructions(manifestPath, len(candidates), 3072)
	if !strings.Contains(instructions, "git-filter-repo --invert-paths") {
		t.Errorf("Instructions missing git-filter-repo command string")
	}

	instructionsEmpty := FormatInstructions("", 0, 0)
	if !strings.Contains(instructionsEmpty, "unslop-git-filter.txt") {
		t.Errorf("FormatInstructions empty path failed")
	}

	// Test write error on invalid file path
	err = WriteFilterManifest(candidates, "/proc/invalid/path/manifest.txt")
	if err == nil {
		t.Errorf("Expected error for invalid output path, got nil")
	}
}
