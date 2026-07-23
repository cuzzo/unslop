package repo

import (
	"bytes"
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
