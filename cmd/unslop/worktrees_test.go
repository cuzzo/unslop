package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/worktree"
)

func TestWorktreeCommandReportsGitEvidence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	path := createTestRepoForSubcommand(t)
	defer os.RemoveAll(path)
	for _, args := range [][]string{
		{"worktrees", "-repo", path, "-json"},
		{"worktrees", "-path", path, "-json"},
		{"worktrees", "-non-interactive", path},
	} {
		var output, diagnostic bytes.Buffer
		if code := worktreeCommand(t, args, nil, &output, &diagnostic); code != 0 {
			t.Fatalf("code=%d diagnostic=%s", code, &diagnostic)
		}
		if args[len(args)-1] == "-json" {
			var report worktree.Report
			if err := json.Unmarshal(output.Bytes(), &report); err != nil || len(report.Worktrees) != 1 || len(report.Errors) != 0 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		} else if !strings.Contains(output.String(), "[Repos]") || !strings.Contains(output.String(), "Main branch:") {
			t.Fatalf("report missing: %s", &output)
		}
	}
}

func TestRepositoryTabDiscoversHomeWithoutRepositoryArguments(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	for _, name := range []string{"alpha", "beta"} {
		path := createTestRepoForSubcommand(t)
		defer os.RemoveAll(path)
		if err := os.Rename(path, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	var output, diagnostic bytes.Buffer
	if code := worktreeCommand(t, []string{"repos", "-json"}, nil, &output, &diagnostic); code != 0 {
		t.Fatalf("default discovery: code=%d diagnostic=%s", code, &diagnostic)
	}
	var report worktree.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || len(report.Worktrees) != 2 || len(report.Errors) != 0 {
		t.Fatalf("standalone repositories missing: %+v %v", report, err)
	}
	for _, item := range report.Worktrees {
		if !item.Primary || item.Obsolete || item.Path != item.Repository {
			t.Fatalf("unsafe repository classification: %+v", item)
		}
	}
}

func TestRepositoryTabAnalysesOnlySelectedRepositories(t *testing.T) {
	if repositoryTestProcess(t) {
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	for _, name := range []string{"alpha", "beta"} {
		path := createTestRepoForSubcommand(t)
		defer os.RemoveAll(path)
		if err := os.Rename(path, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("git", "-C", filepath.Join(home, name), "worktree", "add", "-b", "old", filepath.Join(home, name+"-old")).CombinedOutput(); err != nil {
			t.Fatalf("%s %v", output, err)
		}
	}
	details := filepath.Join(home, "details")
	t.Setenv("UNSLOP_DETAIL_ROWS", details)
	trace := filepath.Join(home, "git.trace")
	t.Setenv("GIT_TRACE", trace)
	for _, selected := range []bool{false, true} {
		script := "exit 130"
		if selected {
			script = `case "$*" in *Branches\>*) cat > "$UNSLOP_DETAIL_ROWS";; *) printf '\0\060\0';; esac`
		}
		cliSelector(t, script)
		if err := os.WriteFile(trace, nil, 0600); err != nil {
			t.Fatal(err)
		}
		var output, diagnostic bytes.Buffer
		if code := worktreeCommand(t, []string{"repos"}, nil, &output, &diagnostic); code != 0 {
			t.Fatalf("selected=%t code=%d diagnostic=%s", selected, code, &diagnostic)
		}
		commands, err := os.ReadFile(trace)
		if err != nil || strings.Contains(string(commands), "for-each-ref") != selected {
			t.Fatalf("history was not deferred until selection: %s %v", commands, err)
		}
		for _, line := range strings.Split(string(commands), "\n") {
			if strings.Contains(line, "for-each-ref") && strings.Contains(line, "/beta") {
				t.Fatalf("unselected repository was analysed: %s", line)
			}
		}
		if selected {
			rows, err := os.ReadFile(details)
			if err != nil || !strings.Contains(string(rows), "[MAIN] main") || !strings.Contains(string(rows), "Checkouts and cleanup candidates") || strings.Contains(string(rows), "unchecked") {
				t.Fatalf("selected repository evidence missing: %s %v", rows, err)
			}
		}
	}
}

type failedWorktreeWriter struct{}

func (failedWorktreeWriter) Write(p []byte) (int, error) {
	return 0, errors.New("closed report stream")
}

func TestWorktreeCommandCommonFailures(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"worktrees", "-help"}, 0},
		{[]string{"worktrees", "-unknown"}, 2},
		{[]string{"repos", "-days", "0"}, 2},
		{[]string{"repos", "-days", "-1"}, 2},
		{[]string{"worktrees", "-path", filepath.Join(home, "missing"), "-json"}, 1},
		{[]string{"worktrees", "-repo", home, "-json"}, 1},
		{[]string{"worktrees", "-non-interactive"}, 0},
	} {
		var diagnostic bytes.Buffer
		if code := worktreeCommand(t, tc.args, nil, io.Discard, &diagnostic); code != tc.code {
			t.Fatalf("args=%v code=%d diagnostic=%s", tc.args, code, &diagnostic)
		}
	}
	var diagnostic bytes.Buffer
	if command, rest := splitCommand(nil); command != "" || rest != nil {
		t.Fatalf("empty invocation: %q %v", command, rest)
	}
	if code := worktreeCommand(t, []string{"-help"}, nil, io.Discard, &diagnostic); code != 0 || !strings.Contains(diagnostic.String(), "unslop worktrees") {
		t.Fatalf("worktree view missing from help: %s", &diagnostic)
	}
	diagnostic.Reset()
	if code := worktreeCommand(t, []string{"worktrees", "-path", home, "-json"}, nil, failedWorktreeWriter{}, &diagnostic); code != 1 || !strings.Contains(diagnostic.String(), "closed report stream") {
		t.Fatalf("write failure code=%d diagnostic=%s", code, &diagnostic)
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if code := worktreeCommand(t, []string{"worktrees"}, nil, io.Discard, io.Discard); code != 1 {
		t.Fatalf("missing home code=%d", code)
	}
}

func cliSelector(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX selector fixture")
	}
	bin := t.TempDir()
	prelude := `
if [ -n "$UNSLOP_FIXTURE_SELECTOR_READY" ]; then touch "$UNSLOP_FIXTURE_SELECTOR_READY"; fi
for argument in "$@"; do
 case "$argument" in
  --bind=every*)
   live_directory="${argument#*cat \'}"
   live_directory="${live_directory%%/footer*}"
   while ! /usr/bin/grep -F 'unbind(every' "$live_directory/actions" >/dev/null 2>&1; do /bin/sleep .01; done
   exec 0<"$live_directory/rows"
   ;;
 esac
done
`
	if err := os.WriteFile(filepath.Join(bin, "fzf"), []byte("#!/bin/sh\n"+prelude+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRepositorySelectorStartsBeforeDiscovery(t *testing.T) {
	if repositoryTestProcess(t) {
		return
	}
	path := createTestRepoForSubcommand(t)
	defer os.RemoveAll(path)
	nativeGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "selector-ready")
	t.Setenv("UNSLOP_FIXTURE_SELECTOR_READY", ready)
	t.Setenv("UNSLOP_FIXTURE_NATIVE_GIT", nativeGit)
	cliSelector(t, "cat")
	bin := t.TempDir()
	proxy := `#!/bin/sh
attempt=0
while [ ! -f "$UNSLOP_FIXTURE_SELECTOR_READY" ] && [ "$attempt" -lt 30 ]; do
 /bin/sleep .01
 attempt=$((attempt + 1))
done
if [ ! -f "$UNSLOP_FIXTURE_SELECTOR_READY" ]; then echo 'discovery preceded selector' >&2; exit 2; fi
exec "$UNSLOP_FIXTURE_NATIVE_GIT" "$@"
`
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(proxy), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var diagnostic bytes.Buffer
	if code := worktreeCommand(t, []string{"repos", "-repo", path}, nil, io.Discard, &diagnostic); code != 0 {
		t.Fatalf("selector did not open before discovery: code=%d %s", code, &diagnostic)
	}
}

func TestWorktreeCommandSelectorFailuresAndSelection(t *testing.T) {
	if repositoryTestProcess(t) {
		return
	}
	for _, tc := range []struct {
		script string
		code   int
	}{
		{"exec /bin/cat", 0},
		{"exit 2", 1},
	} {
		t.Run(tc.script, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			path := createTestRepoForSubcommand(t)
			defer os.RemoveAll(path)
			cliSelector(t, tc.script)
			var output, diagnostic bytes.Buffer
			if code := worktreeCommand(t, []string{"worktrees", "-repo", path}, nil, &output, &diagnostic); code != tc.code {
				t.Fatalf("code=%d diagnostic=%s", code, &diagnostic)
			}
		})
	}
}

func TestTabsPreserveFileCleanupArguments(t *testing.T) {
	if repositoryTestProcess(t) {
		return
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	path := createTestRepoForSubcommand(t)
	defer os.RemoveAll(path)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("UNSLOP_JOURNAL_PATH", filepath.Join(home, "journal.json"))
	t.Setenv("UNSLOP_FIXTURE_FZF_STATE", filepath.Join(home, "state"))
	cache := filepath.Join(path, ".zig-cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "cache.bin"), []byte("cache fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	cliSelector(t, `if [ ! -f "$UNSLOP_FIXTURE_FZF_STATE" ]; then
  printf 'first\n' > "$UNSLOP_FIXTURE_FZF_STATE"
  printf 'ctrl-w\0'
else
  read mode < "$UNSLOP_FIXTURE_FZF_STATE"
  if [ "$mode" = first ]; then
    printf 'second\n' > "$UNSLOP_FIXTURE_FZF_STATE"
    printf 'ctrl-f\0'
  else
    exec /bin/cat
  fi
fi`)
	var output, diagnostic bytes.Buffer
	args := []string{"-path", path, "-min-days", "0", "-min-size-mb", "0.000001", "-apply", "-force-permanent"}
	if code := worktreeCommand(t, args, strings.NewReader("y\n"), &output, &diagnostic); code != 0 {
		t.Fatalf("code=%d output=%s diagnostic=%s", code, &output, &diagnostic)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("file cleanup flags lost after tab switch: %v output=%s", err, &output)
	}
	if _, err := os.Stat(filepath.Join(path, ".git")); err != nil {
		t.Fatal("Worktrees tab altered Git metadata", err)
	}
}

func TestRepositoryDetailsReturnToFilesOrReportSelectorFailure(t *testing.T) {
	if repositoryTestProcess(t) {
		return
	}
	path := createTestRepoForSubcommand(t)
	defer os.RemoveAll(path)
	if output, err := exec.Command("git", "-C", path, "worktree", "add", "-b", "old", filepath.Join(t.TempDir(), "linked")).CombinedOutput(); err != nil {
		t.Fatalf("%s %v", output, err)
	}
	for _, tc := range []struct {
		details string
		code    int
	}{
		{"printf 'f\\0'", 0},
		{"exit 2", 1},
	} {
		t.Run(tc.details, func(t *testing.T) {
			cliSelector(t, `case "$*" in *Branches\>*) `+tc.details+`;; *) printf '\0\060\0';; esac`)
			var next []string
			var diagnostic bytes.Buffer
			code := runWorktreesSubcommand([]string{"-repo", path}, io.Discard, &diagnostic, &next)
			if code != tc.code || (code == 0 && strings.Join(next, "\x00") != "files\x00-path\x00"+path) {
				t.Fatalf("code=%d next=%v diagnostic=%s", code, next, &diagnostic)
			}
		})
	}
}

func TestWorktreeTabOpensFilesWithoutApplying(t *testing.T) {
	if repositoryTestProcess(t) {
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("UNSLOP_FIXTURE_FZF_STATE", filepath.Join(home, "state"))
	cliSelector(t, `if [ ! -f "$UNSLOP_FIXTURE_FZF_STATE" ]; then
  printf 'done\n' > "$UNSLOP_FIXTURE_FZF_STATE"
  printf 'ctrl-f\0'
else
  exec /bin/cat
fi`)
	if code := worktreeCommand(t, []string{"worktrees", "-path", home}, nil, io.Discard, io.Discard); code != 0 {
		t.Fatalf("tab switch code=%d", code)
	}
}

func TestTabsPreserveRepositoryInspectionArguments(t *testing.T) {
	if repositoryTestProcess(t) {
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	path := createTestRepoForSubcommand(t)
	defer os.RemoveAll(path)
	if err := os.Mkdir(filepath.Join(path, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "nested", ".git"), []byte("broken registry fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UNSLOP_FIXTURE_FZF_STATE", filepath.Join(home, "state"))
	cliSelector(t, `count=0
if [ -f "$UNSLOP_FIXTURE_FZF_STATE" ]; then read count < "$UNSLOP_FIXTURE_FZF_STATE"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$UNSLOP_FIXTURE_FZF_STATE"
case "$count" in
  1) printf 'f\0';;
  2) printf 'r\0';;
  *) exit 130;;
esac`)
	var output, diagnostic bytes.Buffer
	if code := worktreeCommand(t, []string{"repos", "-repo", path}, nil, &output, &diagnostic); code != 0 {
		t.Fatalf("repository inspection changed to recursive discovery: code=%d diagnostic=%s", code, &diagnostic)
	}
}

func worktreeCommand(t *testing.T, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	t.Helper()
	defer func() {
		if crash := recover(); crash != nil {
			t.Fatalf("worktree command crashed: %v", crash)
		}
	}()
	return run(args, stdin, stdout, stderr)
}

func repositoryTestProcess(t *testing.T) bool {
	t.Helper()
	if os.Getenv("UNSLOP_REPOSITORY_TEST") == t.Name() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(), "UNSLOP_REPOSITORY_TEST="+t.Name())
	if directory := flag.Lookup("test.gocoverdir"); directory != nil && directory.Value.String() != "" {
		cmd.Args = append(cmd.Args, "-test.gocoverdir="+directory.Value.String())
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("repository process: %s %v", output, err)
	}
	return true
}
