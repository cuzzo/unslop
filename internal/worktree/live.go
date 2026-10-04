package worktree

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yahn/unslop/internal/ui"
)

func progressFooter(progress Progress, elapsed time.Duration) string {
	percent := 0.0
	if total := progress.Completed + progress.Pending; total > 0 {
		percent = math.Min(99, 100*float64(progress.Completed)/float64(total))
	}
	label := "Scanning"
	if progress.Done {
		percent, label = 100, "Scan complete"
	}
	return fmt.Sprintf("%s %s ~%.0f%% | %d dirs | %s | %s | errors: %d", label,
		ui.RenderProgressBar(percent, 16), percent, progress.Completed,
		elapsed.Round(time.Second), ui.SanitizeTerminalString(progress.Path), len(progress.Report.Errors))
}

func ChooseLive(roots, repositories []string, fzfBin string, stderr io.Writer) ([]Worktree, bool, Report, error) {
	var report Report
	started := time.Now()
	output, err := ui.RunLive(selectorCommand(fzfBin, stderr), func(ctx context.Context, publish func(ui.LiveUpdate)) {
		report = DiscoverLive(ctx, roots, repositories, func(progress Progress) {
			rows, _ := repositoryRows(progress.Report.Worktrees)
			publish(ui.LiveUpdate{Rows: rows.Bytes(), Footer: progressFooter(progress, time.Since(started)), Done: progress.Done})
		})
	})
	_, tokens := repositoryRows(report.Worktrees)
	selected, files, err := selectedOutput(output, err, tokens)
	return selected, files, report, err
}

func ChooseProjectLive(group []Worktree, days int, fzfBin string, stderr io.Writer) (Project, bool, bool, error) {
	directory, err := os.MkdirTemp("", "unslop-branches-")
	if err != nil {
		return Project{}, false, false, err
	}
	defer os.RemoveAll(directory)
	cmd := exec.Command(fzfBin, "--read0", "--print0", "--layout=reverse", "--no-sort", "--delimiter=\t", "--with-nth=2..", "--expect=ctrl-f", "--header=[Repos] Branches and commits | f: Files | r/Esc: Back | q: Quit | /: Search\nUp/Down: Branch | Shift-Up/Down: Scroll commits", "--bind=f:print(f)+accept,r:print(r)+accept,esc:print(r)+accept,q:abort,enter:ignore,/:unbind(f)+unbind(r)+unbind(q)+change-prompt(Search branches> )", "--prompt=Branches> ", "--preview=cat '"+strings.ReplaceAll(directory, "'", "'\\''")+"'/{1}", "--preview-window=right,60%,wrap")
	cmd.Stderr = stderr
	var project Project
	output, err := ui.RunLive(cmd, func(ctx context.Context, publish func(ui.LiveUpdate)) {
		publish(ui.LiveUpdate{Footer: "Checking branches and full history " + ui.RenderProgressBar(0, 16)})
		project = AnalyzeProject(ctx, group, days)
		rows, writeErr := projectRows(project, directory)
		if writeErr != nil {
			project.Errors = append(project.Errors, writeErr.Error())
		}
		footer := "Main: " + ui.SanitizeTerminalString(project.MainBranch) + " | " + ui.SanitizeTerminalString(project.MainRepository) + " " + ui.RenderProgressBar(100, 16)
		if len(project.Errors) > 0 {
			footer = "Checks incomplete; no cleanup candidates"
		}
		publish(ui.LiveUpdate{Rows: rows, Footer: footer, Done: true})
	})
	_, files, selectErr := selectedOutput(output, err, nil)
	back := bytes.Contains(output, []byte("r\x00"))
	return project, files, back, selectErr
}

func projectRows(project Project, directory string) ([]byte, error) {
	var overview bytes.Buffer
	PrintProject(Project{Days: project.Days, MainRepository: project.MainRepository, MainBranch: project.MainBranch, Worktrees: project.Worktrees, Errors: project.Errors}, &overview)
	if err := os.WriteFile(filepath.Join(directory, "meta"), overview.Bytes(), 0600); err != nil {
		return nil, err
	}
	branches := append([]Branch{}, project.Branches...)
	isMain := func(branch Branch) bool {
		return branch.Repository == project.MainRepository && branch.Name == project.MainBranch
	}
	sort.SliceStable(branches, func(i, j int) bool {
		if isMain(branches[i]) != isMain(branches[j]) {
			return isMain(branches[i])
		}
		localI, localJ := strings.HasPrefix(branches[i].Name, "refs/heads/"), strings.HasPrefix(branches[j].Name, "refs/heads/")
		if localI != localJ {
			return localI
		}
		return branches[i].LastCommit > branches[j].LastCommit
	})
	var rows bytes.Buffer
	shown := make(map[string]bool)
	for index, branch := range branches {
		if shown[branch.Head] || (len(branch.Commits) == 0 && !isMain(branch)) {
			continue
		}
		shown[branch.Head] = true
		var preview bytes.Buffer
		fmt.Fprintf(&preview, "%s\n\n", ui.SanitizeTerminalString(project.MainRepository))
		for _, alias := range project.Branches {
			if alias.Head == branch.Head {
				fmt.Fprintf(&preview, "%s | %s\n", ui.SanitizeTerminalString(alias.Name), ui.SanitizeTerminalString(alias.Repository))
			}
		}
		fmt.Fprintf(&preview, "\nDistinct work in the last %d days", project.Days)
		if isMain(branch) {
			fmt.Fprint(&preview, " (main branch history)")
		}
		fmt.Fprintln(&preview)
		for _, commit := range branch.Commits {
			fmt.Fprintf(&preview, "%s %s %s\n", commit.Date, commit.Hash, ui.SanitizeTerminalString(commit.Subject))
		}
		token := strconv.Itoa(index)
		if err := os.WriteFile(filepath.Join(directory, token), preview.Bytes(), 0600); err != nil {
			return nil, err
		}
		label := strings.TrimPrefix(branch.Name, "refs/heads/")
		if isMain(branch) {
			label = "[MAIN] " + label
		}
		fmt.Fprintf(&rows, "%s\t%s | %d commits | checked out: %t | local: %t\x00", token, ui.SanitizeTerminalString(label), len(branch.Commits), branch.CheckedOut, branch.LocalOnly)
	}
	fmt.Fprint(&rows, "meta\tCheckouts and cleanup candidates\x00")
	return rows.Bytes(), nil
}
