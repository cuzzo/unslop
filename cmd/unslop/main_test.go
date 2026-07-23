package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/executor"
	"github.com/yahn/unslop/internal/scanner"
)

func TestMinDaysFlagParsing(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "app.exe")

	content := append([]byte("MZ"), bytes.Repeat([]byte("X"), 2*1024*1024)...)
	if err := os.WriteFile(testFile, content, 0755); err != nil {
		t.Fatalf("Failed to write test binary: %v", err)
	}

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	_ = os.Chtimes(testFile, oldTime, oldTime)

	manifestPath := filepath.Join("..", "..", "manifest.json")
	manifest, err := config.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	engine := config.NewRuleEngine(manifest)

	// Scan with minDays = 14 (file age 10d -> excluded)
	cand14 := scanner.ScanParallel([]string{tmpDir}, engine, 14.0, 0, 0, true)
	if len(cand14) != 0 {
		t.Errorf("Expected 0 candidates with minDays 14 (file age 10d); got %d", len(cand14))
	}

	// Scan with minDays = 5 (file age 10d -> included & tagged IsDevBinary)
	cand5 := scanner.ScanParallel([]string{tmpDir}, engine, 5.0, 0, 0, true)
	if len(cand5) != 1 {
		t.Fatalf("Expected 1 candidate with minDays 5; got %d", len(cand5))
	}

	if !cand5[0].IsDevBinary {
		t.Errorf("Expected candidate to have IsDevBinary set to true")
	}

	// Test executor rendering includes [DEV BINARY]
	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("n\n")
	_ = executor.ConfirmAndDeleteWithIO(cand5, true, true, false, stdin, &stdout, &stderr, 1000000, 500000, 500000, manifest)

	outStr := stdout.String()
	if !strings.Contains(outStr, "[DEV BINARY]") {
		t.Errorf("Expected [DEV BINARY] tag in executor output; got:\n%s", outStr)
	}
}

func TestMinDaysNegativeError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-min-days=-5"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Expected exit code 2 for negative -min-days; got %d", code)
	}
	if !strings.Contains(stderr.String(), "-min-days cannot be negative") {
		t.Errorf("Expected negative error message; got: %s", stderr.String())
	}
}
