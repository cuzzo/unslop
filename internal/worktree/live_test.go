package worktree

import (
	"context"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLiveProgressAndCancellation(t *testing.T) {
	defer failOnCrash(t)
	for _, tc := range []struct {
		progress Progress
		want     string
	}{
		{Progress{}, "~0%"},
		{Progress{Completed: 4, Pending: 4, Path: "a\x1bb"}, "~50%"},
		{Progress{Completed: 4, Pending: 12}, "~25%"},
		{Progress{Completed: 4}, "~99%"},
		{Progress{Completed: 4, Done: true}, "Scan complete"},
	} {
		text := progressFooter(tc.progress, 2*time.Second)
		if !strings.Contains(text, tc.want) || !strings.Contains(text, "2s") || strings.Contains(text, "\x1b") {
			t.Fatalf("bad progress footer: %q", text)
		}
	}
	root := testRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if report := DiscoverLive(ctx, nil, []string{root}, func(Progress) { t.Fatal("cancelled discovery ran") }); len(report.Worktrees) != 0 || len(report.Errors) != 0 {
		t.Fatalf("cancelled report: %+v", report)
	}
	ctx, cancel = context.WithCancel(context.Background())
	report := DiscoverLive(ctx, []string{root, root}, nil, func(Progress) { cancel() })
	if len(report.Worktrees) != 0 || len(report.Errors) != 0 {
		t.Fatalf("cancellation during a directory visit: %+v", report)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	gitProxy(t, `if [ "$6" = worktree ]; then : > "$UNSLOP_LIVE_MARKER"; exec /bin/sleep 60; fi`)
	marker := filepath.Join(t.TempDir(), "git-started")
	t.Setenv("UNSLOP_LIVE_MARKER", marker)
	go func() {
		for ctx.Err() == nil {
			if _, err := os.Stat(marker); err == nil {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	watchdog := time.AfterFunc(5*time.Second, cancel)
	defer watchdog.Stop()
	report = DiscoverLive(ctx, nil, []string{root, root}, func(Progress) {})
	if len(report.Errors) != 0 {
		t.Fatalf("stopping active Git reported an error: %+v", report)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryProgressCountsTheExpandingFrontier(t *testing.T) {
	defer failOnCrash(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"a/deeper", "b", ".giga/tmp/.tmpfMFOB3"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "a", "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	var updates []Progress
	report := DiscoverLive(context.Background(), []string{root}, nil, func(update Progress) { updates = append(updates, update) })
	if len(report.Errors) != 0 || len(updates) != 5 {
		t.Fatalf("progress traversal: %+v %+v", report, updates)
	}
	for index, want := range []struct {
		path               string
		completed, pending int
		done               bool
	}{
		{root, 0, 1, false},
		{filepath.Join(root, "a"), 1, 2, false},
		{filepath.Join(root, "b"), 2, 2, false},
		{filepath.Join(root, "a", "deeper"), 3, 1, false},
		{"", 4, 0, true},
	} {
		update := updates[index]
		if update.Path != want.path || update.Completed != want.completed || update.Pending != want.pending || update.Done != want.done {
			t.Fatalf("incorrect directory work at update %d: %+v want %+v", index, update, want)
		}
	}
}

func TestLiveSelectorPublishesAndStops(t *testing.T) {
	if liveTestProcess(t) {
		return
	}
	defer failOnCrash(t)
	root := testRepo(t)
	second := testRepo(t)
	linked(t, second, "old")
	selector := testSelector(t, "cat > /dev/null; /bin/sleep .5; printf '\\060\\0'")
	selected, files, report, err := ChooseLive(nil, []string{second, root}, selector, io.Discard)
	if err != nil || files || len(selected) != 2 || selected[0].Repository != second || len(report.Worktrees) != 3 {
		t.Fatalf("live selection: %v %t %+v %v", selected, files, report, err)
	}
	selected, files, _, err = ChooseLive([]string{root}, nil, testSelector(t, "printf '\\0f\\0'; exit 1"), io.Discard)
	if err != nil || !files || len(selected) != 0 {
		t.Fatalf("live tab switch: %v %t %v", selected, files, err)
	}
	if _, _, _, err := ChooseLive(nil, nil, filepath.Join(root, "missing-fzf"), io.Discard); err == nil {
		t.Fatal("missing selector accepted")
	}
	t.Setenv("TMPDIR", filepath.Join(root, "missing"))
	if _, _, _, err := ChooseLive(nil, nil, selector, io.Discard); err == nil {
		t.Fatal("invalid temporary directory accepted")
	}
}

func TestLiveSelectorReportsProgressWhileGitIsBusy(t *testing.T) {
	if liveTestProcess(t) {
		return
	}
	defer failOnCrash(t)
	t.Setenv("TMPDIR", t.TempDir())
	first, second := testRepo(t), testRepo(t)
	linked(t, first, "old")
	t.Setenv("UNSLOP_LIVE_SECOND", second)
	gitProxy(t, `if [ "$3" = "$UNSLOP_LIVE_SECOND" ]; then exec /bin/sleep 60; fi`)
	selector := testSelector(t, `attempt=0
while [ "$attempt" -lt 200 ]; do
 for directory in "$TMPDIR"/ur-*; do
  if grep -F '~50%' "$directory/footer" >/dev/null 2>&1; then
   if grep -F 'unbind' "$directory/actions" >/dev/null 2>&1; then exit 2; fi
   printf '0\000'
   exit 0
  fi
 done
 /bin/sleep .01
 attempt=$((attempt + 1))
done
exit 2`)
	selected, files, report, err := ChooseLive(nil, []string{first, second}, selector, io.Discard)
	if err != nil || files || len(selected) != 2 || selected[0].Repository != first || len(report.Errors) != 0 {
		t.Fatalf("progress or partial selection missing: %+v %t %+v %v", selected, files, report, err)
	}
}

func TestLiveSelectorReportsPublicationFailures(t *testing.T) {
	if liveTestProcess(t) {
		return
	}
	for _, fault := range []string{"rows.next", "rows", "footer.next", "actions"} {
		t.Run(fault, func(t *testing.T) {
			defer failOnCrash(t)
			t.Setenv("TMPDIR", t.TempDir())
			root := testRepo(t)
			ready := filepath.Join(t.TempDir(), "ready")
			t.Setenv("UNSLOP_PUBLICATION_READY", ready)
			gitProxy(t, `while [ ! -f "$UNSLOP_PUBLICATION_READY" ]; do /bin/sleep .01; done`)
			script := `for directory in "$TMPDIR"/ur-*; do rm -f "$directory/` + fault + `"; mkdir "$directory/` + fault + `"; done
touch "$UNSLOP_PUBLICATION_READY"
cat > /dev/null
exec /bin/sleep 60`

			if _, _, _, err := ChooseLive(nil, []string{root}, testSelector(t, script), io.Discard); err == nil {
				t.Fatal("publication failure was hidden")
			}
		})
	}
}

func liveTestProcess(t *testing.T) bool {
	t.Helper()
	if os.Getenv("UNSLOP_LIVE_TEST") == t.Name() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(), "UNSLOP_LIVE_TEST="+t.Name())
	if directory := flag.Lookup("test.gocoverdir"); directory != nil && directory.Value.String() != "" {
		cmd.Args = append(cmd.Args, "-test.gocoverdir="+directory.Value.String())
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("live process: %s %v", output, err)
	}
	return true
}

func TestLiveSelectorPipeLimit(t *testing.T) {
	if os.Getenv("UNSLOP_LIVE_PIPE_LIMIT") == "1" {
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
		limit.Cur = 64
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
		var files []*os.File
		for {
			file, err := os.Open(os.DevNull)
			if err != nil {
				break
			}
			files = append(files, file)
		}
		files[len(files)-1].Close()
		_, _, _, err := ChooseLive(nil, nil, "/bin/cat", io.Discard)
		for _, file := range files {
			file.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "too many open files") {
			t.Fatalf("pipe resource error: %v", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLiveSelectorPipeLimit$")
	if directory := flag.Lookup("test.gocoverdir"); directory != nil && directory.Value.String() != "" {
		cmd.Args = append(cmd.Args, "-test.gocoverdir="+directory.Value.String())
	}
	cmd.Env = append(os.Environ(), "UNSLOP_LIVE_PIPE_LIMIT=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pipe limit: %s %v", output, err)
	}
}
