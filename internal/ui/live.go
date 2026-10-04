package ui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yahn/unslop/internal/scanner"
)

type LiveUpdate struct {
	Rows   []byte
	Footer string
	Done   bool
}

func RunLive(cmd *exec.Cmd, produce func(context.Context, func(LiveUpdate))) ([]byte, error) {
	directory, err := os.MkdirTemp("", "ur-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	quote := func(path string) string { return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'" }
	cmd.Args = append(cmd.Args, "--no-sync", "--track", "--id-nth=1", "--bind=every(0.2):transform-footer(cat "+quote(filepath.Join(directory, "footer"))+" 2>/dev/null)+transform(cat "+quote(filepath.Join(directory, "actions"))+" 2>/dev/null)", "--footer=Loading "+RenderProgressBar(0, 16))
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan LiveUpdate, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		produce(ctx, func(update LiveUpdate) {
			select {
			case updates <- update:
			case <-ctx.Done():
			}
		})
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for {
		select {
		case err := <-exited:
			cancel()
			<-finished
			return output.Bytes(), err
		case latest := <-updates:
			action := "reload-sync(cat " + quote(filepath.Join(directory, "rows")) + ")"
			if latest.Done {
				action = "unbind(every(0.2))+" + action
			}
			for _, file := range []struct {
				name string
				data []byte
			}{{"rows", latest.Rows}, {"footer", []byte(latest.Footer)}, {"actions", []byte(action)}} {
				path := filepath.Join(directory, file.name)
				err = os.WriteFile(path+".next", file.data, 0600)
				if err == nil {
					err = os.Rename(path+".next", path)
				}
				if err != nil {
					cancel()
					cmd.Process.Kill()
					<-exited
					<-finished
					return nil, err
				}
			}
		}
	}
}

func ChooseFilesLive(fzfBin string, diskTotal, diskUsed, diskFree uint64, scan func(context.Context, func(scanner.Progress)) ([]scanner.Candidate, error)) ([]scanner.Candidate, bool, error) {
	var candidates []scanner.Candidate
	var scanErr error
	started := time.Now()
	output, err := RunLive(fileSelector(fzfBin, diskTotal, diskUsed, diskFree), func(ctx context.Context, publish func(LiveUpdate)) {
		candidates, scanErr = scan(ctx, func(progress scanner.Progress) {
			percent := 0.0
			if progress.Total > 0 {
				percent = 100 * float64(progress.Completed) / float64(progress.Total)
			}
			label := "Scanning files"
			if progress.Done {
				percent = 100
				label = "Scan complete"
			}
			rows, _ := fileRows(progress.Candidates)
			publish(LiveUpdate{rows.Bytes(), fmt.Sprintf("%s %s | %d files | %d candidates | %s", label, RenderProgressBar(percent, 16), progress.Files, len(progress.Candidates), time.Since(started).Round(time.Second)), progress.Done})
		})
		if ctx.Err() == nil && scanErr != nil {
			rows, _ := fileRows(candidates)
			publish(LiveUpdate{rows.Bytes(), "Scan incomplete: " + SanitizeTerminalString(scanErr.Error()), true})
		}
	})
	_, tokens := fileRows(candidates)
	selected, tab, selectErr := selectedFiles(output, err, tokens)
	if selectErr != nil {
		return nil, false, selectErr
	}
	if tab || scanErr == context.Canceled {
		return selected, tab, nil
	}
	return selected, tab, scanErr
}
