package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func createTestRepoForSubcommand(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "unslop-subcmd-test-*")
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

	debugFile := filepath.Join(dir, "debug.pdb")
	_ = os.WriteFile(debugFile, []byte("DEBUG PDB DATA"), 0644)
	execCmd("add", ".")
	execCmd("commit", "-m", "Add debug file")

	return dir
}

func TestRunRepoSubcommand(t *testing.T) {
	repoDir := createTestRepoForSubcommand(t)
	defer os.RemoveAll(repoDir)

	manifestPath := filepath.Join(repoDir, "test-filter.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// Test repo subcommand in non-interactive mode
	exitCode := run([]string{"repo", "-non-interactive", "-min-size", "0.0", "-output", manifestPath, repoDir}, nil, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("runRepoSubcommand returned exit code %d; stderr:\n%s", exitCode, stderr.String())
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "Successfully generated Git history filter file") {
		t.Errorf("Expected success message in stdout:\n%s", outStr)
	}

	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Errorf("Expected manifest file '%s' to be created", manifestPath)
	}

	// Test repo subcommand with -json
	var jsonStdout bytes.Buffer
	var jsonStderr bytes.Buffer
	exitCodeJson := run([]string{"repo", "-json", "-min-size", "0.0", repoDir}, nil, &jsonStdout, &jsonStderr)
	if exitCodeJson != 0 {
		t.Fatalf("runRepoSubcommand with -json returned exit code %d", exitCodeJson)
	}
	if !strings.Contains(jsonStdout.String(), `"debug.pdb"`) {
		t.Errorf("Expected JSON output to contain debug.pdb:\n%s", jsonStdout.String())
	}

	// Test repo subcommand with -dry-run
	var dryStdout bytes.Buffer
	var dryStderr bytes.Buffer
	dryManifest := filepath.Join(repoDir, "dry-filter.txt")
	exitCodeDry := run([]string{"repo", "-non-interactive", "-dry-run", "-min-size", "0.0", "-output", dryManifest, repoDir}, nil, &dryStdout, &dryStderr)
	if exitCodeDry != 0 {
		t.Fatalf("runRepoSubcommand with -dry-run returned exit code %d", exitCodeDry)
	}
	if !strings.Contains(dryStdout.String(), "[DRY RUN]") {
		t.Errorf("Expected [DRY RUN] message in stdout:\n%s", dryStdout.String())
	}

	// Test non-existent repo error
	nonRepoDir, _ := os.MkdirTemp("", "non-repo-*")
	defer os.RemoveAll(nonRepoDir)
	var errStderr bytes.Buffer
	exitCodeErr := run([]string{"repo", nonRepoDir}, nil, io.Discard, &errStderr)
	if exitCodeErr == 0 {
		t.Errorf("Expected non-zero exit code for non-git repository")
	}

	// Test invalid flag error
	var flagErrStderr bytes.Buffer
	exitCodeFlagErr := run([]string{"repo", "-invalid-flag-abc"}, nil, io.Discard, &flagErrStderr)
	if exitCodeFlagErr != 2 {
		t.Errorf("Expected exit code 2 for invalid flag, got %d", exitCodeFlagErr)
	}

	// Test -help flag
	var helpStderr bytes.Buffer
	exitCodeHelp := run([]string{"repo", "-help"}, nil, io.Discard, &helpStderr)
	if exitCodeHelp != 0 {
		t.Errorf("Expected exit code 0 for -help flag, got %d", exitCodeHelp)
	}
}
