package worktree

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testSelector(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX selector fixture")
	}
	if strings.Contains(script, "cat") {
		catCommand := "cat"
		if strings.Contains(script, "exec /bin/cat") {
			catCommand = "exec /bin/cat"
		}
		script = strings.Replace(script, catCommand, `for argument in "$@"; do
 case "$argument" in
  --bind=every*)
   live_directory="${argument#*cat \'}"
   live_directory="${live_directory%%/footer*}"
   while ! /usr/bin/grep -F 'unbind(every' "$live_directory/actions" >/dev/null 2>&1; do /bin/sleep .01; done
   exec 0<"$live_directory/rows"
   ;;
 esac
done
`+catCommand, 1)
	}
	path := filepath.Join(t.TempDir(), "selector")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWorktreeSelector(t *testing.T) {
	items := []Worktree{{Path: "/one", Status: "merged", Obsolete: true}, {Path: "/two\n\x1bunsafe", Status: "outstanding"}}
	for _, tc := range []struct {
		script             string
		want               int
		switchTab, failure bool
	}{
		{"cat", 2, false, false},
		{"printf 'ctrl-f\\0'", 0, true, false},
		{"printf 'ctrl-f\\0'; exit 1", 0, true, false},
		{"printf 'f\\0'", 0, true, false},
		{"printf 'f\\0'; exit 1", 0, true, false},
		{"printf '\\0f\\0'; exit 1", 0, true, false},
		{"printf 'bad\\0-1\\0999\\0'", 0, false, false},
		{"exit 1", 0, false, false},
		{"exit 130", 0, false, false},
		{"exit 2", 0, false, true},
	} {
		t.Run(tc.script, func(t *testing.T) {
			defer failOnCrash(t)
			selected, switchTab, err := chooseTest(items, testSelector(t, tc.script), io.Discard)
			if len(selected) != tc.want || switchTab != tc.switchTab || (err != nil) != tc.failure {
				t.Fatalf("selected=%+v switch=%v err=%v", selected, switchTab, err)
			}
		})
	}
	if _, _, err := chooseTest(items, filepath.Join(t.TempDir(), "missing"), io.Discard); err == nil {
		t.Fatal("missing selector accepted")
	}
}

func TestRepositorySelectorClustersWorktrees(t *testing.T) {
	defer failOnCrash(t)
	items := []Worktree{
		{Repository: "/z/repo", Path: "/z/repo", Status: "merged", Primary: true},
		{Repository: "/a/repo", Path: "/a/feature", Status: "outstanding"},
		{Repository: "/z/repo", Path: "/z/old", Status: "merged", Obsolete: true},
		{Repository: "/a/repo", Path: "/a/repo", Status: "merged", Primary: true},
		{Repository: "/a/repo", Path: "/a/dirty", Status: "merged", Dirty: true},
		{Repository: "/a/repo", Path: "/a/local", Status: "merged", LocalFiles: true},
		{Repository: "/a/repo", Path: "/a/error", Status: "merged", Error: "unreadable"},
	}
	input := filepath.Join(t.TempDir(), "rows")
	arguments := filepath.Join(t.TempDir(), "arguments")
	t.Setenv("UNSLOP_SELECTOR_ROWS", input)
	t.Setenv("UNSLOP_SELECTOR_ARGUMENTS", arguments)
	selector := testSelector(t, `printf '%s\n' "$@" > "$UNSLOP_SELECTOR_ARGUMENTS"
cat > "$UNSLOP_SELECTOR_ROWS"
printf '\0001\000'`)
	selected, filesTab, err := chooseTest(items, selector, io.Discard)
	if err != nil || filesTab || len(selected) != 4 || selected[0].Repository != "/a/repo" || selected[1].Path != "/a/repo" {
		t.Fatalf("cluster selection=%+v files=%v error=%v", selected, filesTab, err)
	}
	rows, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	records := bytes.Split(bytes.TrimSuffix(rows, []byte{0}), []byte{0})
	if len(records) != 2 || !bytes.Contains(records[0], []byte("/a/repo")) || !bytes.Contains(records[0], []byte("review: 3")) || !bytes.Contains(records[1], []byte("review: 0")) || !bytes.Contains(records[1], []byte("obsolete: 1")) {
		t.Fatalf("ungrouped rows: %q", rows)
	}
	args, err := os.ReadFile(arguments)
	if err != nil || !bytes.Contains(args, []byte("--expect=ctrl-f")) || !bytes.Contains(args, []byte("f:print(f)+accept")) || !bytes.Contains(args, []byte("/:unbind(f)")) || !bytes.Contains(args, []byte("[Repos]")) {
		t.Fatalf("missing repo tab shortcuts: %q %v", args, err)
	}
	if _, _, err := chooseTest([]Worktree{{Repository: "/a/repo", Status: "unchecked"}, {Repository: "/a/repo", Path: "/a/old", Status: "unchecked"}}, selector, io.Discard); err != nil {
		t.Fatal(err)
	}
	rows, err = os.ReadFile(input)
	if err != nil || !bytes.Contains(rows, []byte("analyse history")) || bytes.Contains(rows, []byte("obsolete:")) {
		t.Fatalf("discovery claimed analysed counts: %q %v", rows, err)
	}
}

func TestRepositoryGroupsCombineOverlappingRemotes(t *testing.T) {
	defer failOnCrash(t)
	items := []Worktree{
		{Repository: "/a", Path: "/a", Remotes: []string{"host/project"}},
		{Repository: "/b", Path: "/b", Remotes: []string{"host/fork"}},
		{Repository: "/bridge", Path: "/bridge", Remotes: []string{"host/project", "host/fork"}},
		{Repository: "/a", Path: "/a-linked", Remotes: []string{"host/project"}},
		{Repository: "/local", Path: "/local"},
		{Repository: "/other", Path: "/other", Remotes: []string{"host/other"}},
	}
	groups := Groups(items)
	if len(groups) != 3 || len(groups[0]) != 4 || len(groups[1]) != 1 || len(groups[2]) != 1 {
		t.Fatalf("overlapping clone groups incorrect: %+v", groups)
	}
	selected, _, err := chooseTest(items, testSelector(t, "printf '\\0\\060\\0'"), io.Discard)
	if err != nil || len(selected) != 4 || projectLabel(selected) != "host/project" {
		t.Fatalf("combined clone selection=%+v err=%v", selected, err)
	}
}

func chooseTest(items []Worktree, bin string, stderr io.Writer) ([]Worktree, bool, error) {
	rows, tokens := repositoryRows(items)
	cmd := selectorCommand(bin, stderr)
	cmd.Stdin = &rows
	output, err := cmd.Output()
	return selectedOutput(output, err, tokens)
}
