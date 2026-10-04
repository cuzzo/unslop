package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/executor"
	"github.com/yahn/unslop/internal/scanner"
)

func TestIncompleteScanAbortsApply(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	t.Setenv("PATH", "")
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	restricted := filepath.Join(root, "restricted")
	if err := os.Mkdir(restricted, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(restricted, 0700)
	var out, errOut bytes.Buffer
	code := run([]string{"-path", root, "-apply"}, strings.NewReader("y\n"), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "scan incomplete") {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
}

func TestApplyWithoutFzfFailsExplicitly(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("HOME", t.TempDir())
	var out, errOut bytes.Buffer
	code := run([]string{"-path", t.TempDir(), "-apply"}, strings.NewReader("y\n"), &out, &errOut)
	if code == 0 || !strings.Contains(errOut.String(), "fzf") {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
}

func TestIncompleteScanStillPreviewsAccessibleCandidates(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	t.Setenv("PATH", "")
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	cache := filepath.Join(root, ".zig-cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "fixture"), []byte("cache fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	restricted := filepath.Join(root, "restricted")
	if err := os.Mkdir(restricted, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(restricted, 0700)
	for _, interactive := range []bool{false, true} {
		if interactive {
			cliSelector(t, "exec /bin/cat")
		}
		for _, flags := range [][]string{{}, {"-dry-run"}, {"-apply", "-dry-run"}} {
			args := append([]string{"-path", root, "-min-days", "0", "-min-size-mb", "0.000001"}, flags...)
			var output, diagnostic bytes.Buffer
			if code := run(args, nil, &output, &diagnostic); code != 1 || !strings.Contains(output.String(), ".zig-cache") || !strings.Contains(diagnostic.String(), "scan incomplete") {
				t.Fatalf("code=%d output=%s diagnostic=%s", code, &output, &diagnostic)
			}
		}
	}
}

func TestSessionCleanupRequiresBothOptIns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture selector")
	}
	for _, tc := range []struct{ include, applyData bool }{{false, true}, {true, false}, {true, true}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("UNSLOP_JOURNAL_PATH", filepath.Join(home, "journal.json"))
			bin := filepath.Join(home, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			cliSelector(t, "exec /bin/cat")
			paths := []string{filepath.Join(home, ".pi/agent/sessions/project/history.jsonl"), filepath.Join(home, ".gemini/antigravity-cli/brain/history/transcript.jsonl")}
			for _, p := range paths {
				if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("disposable session fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			auth := filepath.Join(home, ".pi/agent/auth.json")
			if err := os.WriteFile(auth, []byte("credential fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-path", home, "-apply", "-force-permanent", "-min-days", "0", "-min-size-mb", "0.000001"}
			if tc.include {
				args = append(args, "-include-data")
			}
			if tc.applyData {
				args = append(args, "-apply-data")
			}
			var out, errOut bytes.Buffer
			if code := run(args, strings.NewReader("y\n"), &out, &errOut); code != 0 {
				t.Fatalf("code=%d out=%s stderr=%s", code, out.String(), errOut.String())
			}
			for _, p := range paths {
				_, err := os.Stat(p)
				if os.IsNotExist(err) != (tc.include && tc.applyData) {
					t.Errorf("unexpected session state: %s: %v", p, err)
				}
			}
			if _, err := os.Stat(auth); err != nil {
				t.Fatal("credentials removed", err)
			}
		})
	}
}

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
	cand14, err := scanner.ScanParallelChecked([]string{tmpDir}, engine, 14.0, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cand14) != 0 {
		t.Errorf("Expected 0 candidates with minDays 14 (file age 10d); got %d", len(cand14))
	}

	// Scan with minDays = 5 (file age 10d -> included & tagged IsDevBinary)
	cand5, err := scanner.ScanParallelChecked([]string{tmpDir}, engine, 5.0, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cand5) != 1 {
		t.Fatalf("Expected 1 candidate with minDays 5; got %d", len(cand5))
	}

	if !cand5[0].IsDevBinary {
		t.Errorf("Expected candidate to have IsDevBinary set to true")
	}

	// Test executor rendering includes [DEV BINARY]
	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("n\n")
	_ = executor.ConfirmAndDeleteWithIO(cand5, true, true, false, stdin, &stdout, &stderr, 500000, manifest)

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
