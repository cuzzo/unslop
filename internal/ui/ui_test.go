package ui

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/yahn/unslop/internal/scanner"
)

func TestFileTabSelectionAndNavigation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX selector fixture")
	}
	items := []scanner.Candidate{{Path: "/safe", CanDelete: true, IsGitIgnored: true}, {Path: "/report"}}
	if rows, _ := fileRows(items); !bytes.Contains(rows.Bytes(), []byte("[GITIGNORE] /safe")) {
		t.Fatalf("ignored-file label missing: %s", &rows)
	}
	for _, tc := range []struct {
		script string
		want   int
		tab    bool
	}{
		{"cat", 1, false},
		{"printf 'ctrl-w\\0'", 0, true},
		{"printf 'ctrl-w\\0'; exit 1", 0, true},
		{"printf 'r\\0'", 0, true},
		{"printf 'r\\0'; exit 1", 0, true},
		{"printf '\\0r\\0'; exit 1", 0, true},
		{"printf 'unknown\\0'", 0, false},
		{"exit 0", 0, false},
		{"exit 1", 0, false},
		{"exit 130", 0, false},
		{"exit 2", 0, false},
	} {
		t.Run(tc.script, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "selector")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+tc.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			rows, tokens := fileRows(items)
			cmd := fileSelector(path, 1, 1, 0)
			cmd.Stdin = &rows
			output, err := cmd.Output()
			selected, tab, _ := selectedFiles(output, err, tokens)
			if len(selected) != tc.want || tab != tc.tab {
				t.Fatalf("selected=%+v tab=%v", selected, tab)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "selector")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'ctrl-w\\0'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(path).Output()
	if _, tab, _ := selectedFiles(output, err, nil); !tab {
		t.Fatal("empty Files tab blocked navigation")
	}
}
