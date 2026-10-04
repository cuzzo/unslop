package worktree

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectRowsKeepBranchesCompactAndCommitsInPreview(t *testing.T) {
	base, copy := projectFixture(t)
	testGit(t, copy, "checkout", "-b", "feature")
	hash := commitFile(t, copy, "feature.txt", "feature", "distinct feature")
	testGit(t, copy, "branch", "alias")
	testGit(t, copy, "update-ref", "refs/remotes/origin/feature", hash)
	project := projectFor(t, base, copy)
	directory := t.TempDir()
	rows, err := projectRows(project, directory)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rows, []byte("[MAIN]")) || bytes.Contains(rows, []byte("distinct feature")) {
		t.Fatalf("commits flooded branch list: %q", rows)
	}
	var previews strings.Builder
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		previews.Write(data)
	}
	if strings.Count(previews.String(), "distinct feature") != 1 || !strings.Contains(previews.String(), "refs/heads/alias") || !strings.Contains(previews.String(), "refs/remotes/origin/feature") || !strings.Contains(previews.String(), "KEEP") {
		t.Fatal(previews.String())
	}
	if _, err := projectRows(project, filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing preview storage accepted")
	}
	blocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(blocked, "0"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := projectRows(project, blocked); err == nil {
		t.Fatal("unwritable branch preview accepted")
	}
}

func TestProjectSelectorSupportsBackFilesAndIncompleteChecks(t *testing.T) {
	base, copy := projectFixture(t)
	a, err := List(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := List(copy)
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"cat", "printf 'r\\0'", "printf 'f\\0'", "exit 2"} {
		project, files, back, err := ChooseProjectLive(append(a, b...), 14, testSelector(t, script), io.Discard)
		if files != (script == "printf 'f\\0'") || back != (script == "printf 'r\\0'") || (err != nil) != (script == "exit 2") {
			t.Fatalf("%s: %+v %t %t %v", script, project, files, back, err)
		}
	}
	gitProxy(t, `if [ "$6" = status ]; then exit 2; fi`)
	project, _, _, err := ChooseProjectLive(append(a, b...), 14, testSelector(t, "cat"), io.Discard)
	if err != nil || len(project.Errors) == 0 {
		t.Fatalf("incomplete checks hidden: %+v %v", project, err)
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, _, _, err := ChooseProjectLive(nil, 14, "unused", io.Discard); err == nil {
		t.Fatal("missing preview temporary root accepted")
	}
}

func TestProjectSelectorReportsPreviewPublicationFailure(t *testing.T) {
	if liveTestProcess(t) {
		return
	}
	t.Setenv("TMPDIR", t.TempDir())
	root := testRepo(t)
	items, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv("UNSLOP_PREVIEW_READY", ready)
	gitProxy(t, `while [ ! -f "$UNSLOP_PREVIEW_READY" ]; do /bin/sleep .01; done`)
	selector := testSelector(t, `for directory in "$TMPDIR"/unslop-branches-*; do mkdir "$directory/meta"; done
touch "$UNSLOP_PREVIEW_READY"
cat`)
	project, _, _, err := ChooseProjectLive(items, 14, selector, io.Discard)
	if err != nil || len(project.Errors) == 0 || !strings.Contains(strings.Join(project.Errors, " "), "directory") {
		t.Fatalf("preview failure hidden: %+v %v", project, err)
	}
}
