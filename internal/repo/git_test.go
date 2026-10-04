package repo

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestHistoryOutputContract(t *testing.T) {
	dir := createTestGitRepo(t)
	defer os.RemoveAll(dir)
	expected := map[string]HistoryCandidate{
		"app.pdb":         {Size: int64(len("DEBUG SYMBOLS CONTENT")), Category: "Debug Binary", Status: "existing", IsDebug: true, CommitCount: 1},
		"node_modules/":   {Size: int64(len("console.log('test')")), Category: "Dependency Dump", Status: "existing", CommitCount: 1},
		"temp_data.bin":   {Size: int64(len("TEMP BINARY CONTENT")), Category: "Deleted Then Ignored", Status: "deleted", CommitCount: 2},
		"trace_dump.json": {Size: int64(len(`{"trace": [1, 2, 3]}`)), Category: "Deleted Then Ignored", Status: "deleted", CommitCount: 2},
	}
	for _, minSize := range []float64{0, 0.5} {
		candidates, err := AnalyzeHistory(dir, ScanOptions{MinSizeMB: minSize, Stderr: io.Discard})
		if err != nil {
			t.Fatal(err)
		}
		wantCount := len(expected)
		if minSize > 0 {
			wantCount--
		}
		if len(candidates) != wantCount {
			t.Fatalf("min-size=%v candidates=%+v", minSize, candidates)
		}
		for index, candidate := range candidates {
			want, found := expected[candidate.Path]
			want.ID, want.Path, want.RiskClass, want.CanDelete = index+1, candidate.Path, "history-bloat", true
			if !found || candidate != want {
				t.Fatalf("min-size=%v got %+v want %+v", minSize, candidate, want)
			}
		}
	}
}

func TestDeletedDependencyHistoryRemainsAnAggregate(t *testing.T) {
	dir := createTestGitRepo(t)
	defer os.RemoveAll(dir)
	cmd := exec.Command("git", "-C", dir, "rm", "-r", "node_modules")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v", output, err)
	}
	cmd = exec.Command("git", "-C", dir, "-c", "commit.gpgsign=false", "commit", "-m", "remove dependencies")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v", output, err)
	}
	items, err := AnalyzeHistory(dir, ScanOptions{Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Path == "node_modules/" {
			if item.Size != 10*1024*1024 || item.Category != "Dependency Dump" || item.Status != "deleted" || item.CommitCount != 2 {
				t.Fatalf("deleted aggregate changed: %+v", item)
			}
			return
		}
	}
	t.Fatal("deleted dependency aggregate missing")
}

func createTestGitRepo(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "unslop-git-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	execCmd := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Git command %v failed: %v\nOutput: %s", args, err, string(out))
		}
	}

	execCmd("init")
	execCmd("config", "user.name", "Test")
	execCmd("config", "user.email", "test@example.com")

	// Commit 1: Add initial files including debug binary, json dump, and node_modules
	debugFile := filepath.Join(dir, "app.pdb")
	_ = os.WriteFile(debugFile, []byte("DEBUG SYMBOLS CONTENT"), 0644)

	jsonDump := filepath.Join(dir, "trace_dump.json")
	_ = os.WriteFile(jsonDump, []byte(`{"trace": [1, 2, 3]}`), 0644)

	deletedFile := filepath.Join(dir, "temp_data.bin")
	_ = os.WriteFile(deletedFile, []byte("TEMP BINARY CONTENT"), 0644)

	nodeModFile := filepath.Join(dir, "node_modules", "pkg", "index.js")
	_ = os.MkdirAll(filepath.Dir(nodeModFile), 0755)
	_ = os.WriteFile(nodeModFile, []byte("console.log('test')"), 0644)

	execCmd("add", ".")
	execCmd("commit", "-m", "Initial commit")

	// Commit 2: Delete temp_data.bin and trace_dump.json, add .gitignore
	_ = os.Remove(deletedFile)
	_ = os.Remove(jsonDump)
	gitignoreFile := filepath.Join(dir, ".gitignore")
	_ = os.WriteFile(gitignoreFile, []byte("temp_data.bin\n"), 0644)

	execCmd("add", ".")
	execCmd("commit", "-m", "Delete temp files and add .gitignore")

	return dir
}

func TestGitAnalyzer(t *testing.T) {
	repoDir := createTestGitRepo(t)
	defer os.RemoveAll(repoDir)

	if !Detect(repoDir) {
		t.Errorf("Detect(%q) = false; want true", repoDir)
	}

	nonRepoDir, _ := os.MkdirTemp("", "non-git-*")
	defer os.RemoveAll(nonRepoDir)
	if Detect(nonRepoDir) {
		t.Errorf("Detect(%q) = true; want false", nonRepoDir)
	}

	opts := ScanOptions{
		MinSizeMB: 0.0,
	}

	candidates, err := AnalyzeHistory(repoDir, opts)
	if err != nil {
		t.Fatalf("AnalyzeHistory failed: %v", err)
	}

	if len(candidates) == 0 {
		t.Fatalf("Expected candidates, got 0")
	}

	hasDebug := false
	hasDepDump := false
	hasDeletedIgnored := false

	for _, c := range candidates {
		if c.IsDebug || c.Category == "Debug Binary" {
			hasDebug = true
		}
		if c.Category == "Dependency Dump" || c.Path == "node_modules/" {
			hasDepDump = true
		}
		if c.Category == "Deleted Then Ignored" || c.Path == "temp_data.bin" {
			hasDeletedIgnored = true
		}
	}

	if !hasDebug {
		t.Errorf("Expected debug binary candidate in history scan")
	}
	if !hasDepDump {
		t.Errorf("Expected dependency dump candidate in history scan")
	}
	if !hasDeletedIgnored {
		t.Errorf("Expected deleted-then-ignored candidate in history scan")
	}

	// Verify size descending sorting order
	for i := 0; i < len(candidates)-1; i++ {
		if candidates[i].Size < candidates[i+1].Size {
			t.Errorf("Candidates not sorted by size descending: index %d size %d < index %d size %d",
				i, candidates[i].Size, i+1, candidates[i+1].Size)
		}
	}
}

func TestGitAnalyzerNonRepoError(t *testing.T) {
	nonRepoDir, _ := os.MkdirTemp("", "non-git-*")
	defer os.RemoveAll(nonRepoDir)

	_, err := AnalyzeHistory(nonRepoDir, ScanOptions{})
	if err == nil {
		t.Errorf("Expected error for non-repo directory, got nil")
	}
}
