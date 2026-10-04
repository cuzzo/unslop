package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunRepoUI(t *testing.T) {
	candidates := []HistoryCandidate{
		{ID: 1, Path: "app.pdb", Size: 1024, Category: "Debug Binary", RiskClass: "history-bloat", Status: "deleted", IsDebug: true},
		{ID: 2, Path: "node_modules/", Size: 5242880, Category: "Dependency Dump", RiskClass: "history-bloat", Status: "existing", IsDebug: false},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// Test non-interactive mode
	selected := RunRepoUI(candidates, "", true, &stdout, &stderr)
	if len(selected) != 2 {
		t.Errorf("Expected 2 selected candidates in non-interactive mode, got %d", len(selected))
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "app.pdb") || !strings.Contains(outStr, "node_modules/") {
		t.Errorf("Stdout output missing candidate paths:\n%s", outStr)
	}

	// Test empty candidates
	var stdoutEmpty bytes.Buffer
	selectedEmpty := RunRepoUI([]HistoryCandidate{}, "", true, &stdoutEmpty, &stderr)
	if len(selectedEmpty) != 0 {
		t.Errorf("Expected 0 selected candidates for empty list, got %d", len(selectedEmpty))
	}
}

func TestHistorySelectorPreservesCandidatesAndSanitizesLabels(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX selector fixture")
	}
	items := []HistoryCandidate{{ID: 1, Path: "dump\n.pdb", Category: "Debug\x1b Binary", Status: "deleted", IsDebug: true}, {ID: 2, Path: "node_modules/", Status: "existing"}}
	rows := filepath.Join(t.TempDir(), "rows")
	t.Setenv("UNSLOP_HISTORY_ROWS", rows)
	selector := filepath.Join(t.TempDir(), "selector")
	if err := os.WriteFile(selector, []byte("#!/bin/sh\ncat > \"$UNSLOP_HISTORY_ROWS\"\ncat \"$UNSLOP_HISTORY_ROWS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	selected := RunRepoUI(items, selector, false, &output, &output)
	if len(selected) != len(items) || selected[0] != items[0] || selected[1] != items[1] {
		t.Fatalf("selection changed candidate identity: %+v", selected)
	}
	data, err := os.ReadFile(rows)
	if err != nil || !bytes.Contains(data, []byte("[DEBUG BINARY] [DELETED] dump.pdb")) || !bytes.Contains(data, []byte("[EXISTING] node_modules/")) || bytes.ContainsAny(data, "\n\x1b") {
		t.Fatalf("invalid selector labels: %q %v", data, err)
	}
}
