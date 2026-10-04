package ui

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/scanner"
)

func liveSelector(t *testing.T, script string) string {
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

func TestLiveFilesReturnSelectionAndScanFailures(t *testing.T) {
	items := []scanner.Candidate{{Path: "/cache", CanDelete: true}, {Path: "/report"}}
	for _, failure := range []bool{false, true} {
		selected, tab, err := ChooseFilesLive(liveSelector(t, "cat"), 10, 5, 5, func(ctx context.Context, update func(scanner.Progress)) ([]scanner.Candidate, error) {
			update(scanner.Progress{Candidates: items, Completed: 1, Total: 2, Files: 3})
			update(scanner.Progress{Candidates: items, Completed: 2, Total: 2, Done: true})
			if failure {
				return items, errors.New("scan incomplete")
			}
			return items, nil
		})
		if len(selected) != 1 || selected[0].Path != "/cache" || tab || (err != nil) != failure {
			t.Fatalf("selection=%+v tab=%t error=%v", selected, tab, err)
		}
	}
}

func TestLiveFilesPublishBeforeCompletionAndCancel(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	selector := liveSelector(t, `attempt=0
while [ "$attempt" -lt 300 ]; do
 for directory in "$TMPDIR"/ur-*; do
  if grep -F '/cache' "$directory/rows" >/dev/null 2>&1; then
   if grep -F 'Scan complete' "$directory/footer" >/dev/null 2>&1; then exit 2; fi
   printf 'cand-1\0'; exit 0
  fi
 done
 /bin/sleep .01
 attempt=$((attempt + 1))
done
exit 2`)
	items := []scanner.Candidate{{Path: "/cache", CanDelete: true}}
	selected, tab, err := ChooseFilesLive(selector, 10, 5, 5, func(ctx context.Context, update func(scanner.Progress)) ([]scanner.Candidate, error) {
		update(scanner.Progress{Candidates: items, Completed: 1, Total: 2})
		<-ctx.Done()
		return items, ctx.Err()
	})
	if err != nil || tab || len(selected) != 1 {
		t.Fatalf("partial selection lost: %+v %t %v", selected, tab, err)
	}
}

func TestLiveFilesTabAndSelectorErrors(t *testing.T) {
	for _, script := range []string{"printf 'r\\0'; exit 1", "exit 2", "exit 130"} {
		_, tab, err := ChooseFilesLive(liveSelector(t, script), 0, 0, 0, func(ctx context.Context, update func(scanner.Progress)) ([]scanner.Candidate, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if tab != strings.Contains(script, "printf") || (err != nil) != (script == "exit 2") {
			t.Fatalf("%s: tab=%t error=%v", script, tab, err)
		}
	}
	if _, err := RunLive(exec.Command(filepath.Join(t.TempDir(), "missing")), func(context.Context, func(LiveUpdate)) { t.Fatal("scan started without selector") }); err == nil {
		t.Fatal("missing selector accepted")
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := RunLive(exec.Command("unused"), func(context.Context, func(LiveUpdate)) { t.Fatal("scan started without temporary storage") }); err == nil {
		t.Fatal("temporary storage failure hidden")
	}
}

func TestLiveProducerStartsAfterSelector(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv("UNSLOP_READY", ready)
	selector := liveSelector(t, `touch "$UNSLOP_READY"; cat`)
	_, err := RunLive(exec.Command(selector), func(ctx context.Context, publish func(LiveUpdate)) {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ready); err == nil {
				publish(LiveUpdate{Rows: []byte("1\tready\x00"), Done: true})
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Error("selector did not launch before producer")
		publish(LiveUpdate{Done: true})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLivePublicationFailureCancelsProducer(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv("UNSLOP_PUBLICATION_READY", ready)
	selector := liveSelector(t, `for directory in "$TMPDIR"/ur-*; do mkdir "$directory/rows.next"; done
touch "$UNSLOP_PUBLICATION_READY"
exec /bin/sleep 60`)
	_, err := RunLive(exec.Command(selector), func(ctx context.Context, publish func(LiveUpdate)) {
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
		publish(LiveUpdate{Rows: []byte("1\tpartial\x00")})
		<-ctx.Done()
	})
	if err == nil {
		t.Fatal("publication failure hidden")
	}
}
