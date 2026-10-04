package worktree

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yahn/unslop/internal/ui"
)

type Report struct {
	Roots     []string   `json:"roots"`
	Worktrees []Worktree `json:"worktrees"`
	Errors    []string   `json:"errors"`
	Projects  []Project  `json:"projects,omitempty"`
}

func Discover(roots, repositories []string, progress io.Writer) Report {
	return scan(roots, repositories, progress, List)
}

type Progress struct {
	Report             Report
	Completed, Pending int
	Path               string
	Done               bool
}

func DiscoverLive(ctx context.Context, roots, repositories []string, update func(Progress)) Report {
	return scanContext(ctx, roots, repositories, io.Discard, func(path string) ([]Worktree, error) { return list(ctx, path) }, update)
}

func scan(roots, repositories []string, progress io.Writer, analyze func(string) ([]Worktree, error)) Report {
	return scanContext(context.Background(), roots, repositories, progress, analyze, func(Progress) {})
}

func scanContext(ctx context.Context, roots, repositories []string, progress io.Writer, analyze func(string) ([]Worktree, error), update func(Progress)) Report {
	report := Report{Roots: append(append([]string{}, roots...), repositories...), Worktrees: []Worktree{}, Errors: []string{}}
	seen := make(map[string]bool)
	registered := make(map[string]bool)

	inspect := func(path string) {
		common, err := gitContext(ctx, path, "rev-parse", "--path-format=absolute", "--git-common-dir")
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			report.Errors = append(report.Errors, path+": "+err.Error())
			return
		}
		common = strings.TrimSuffix(common, "\n")
		if actual, err := filepath.EvalSymlinks(common); err == nil {
			common = actual
		}
		if !seen[common] {
			seen[common] = true
			fmt.Fprintf(progress, "Checking Git worktrees: %s\n", ui.SanitizeTerminalString(path))
			items, err := analyze(path)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				report.Errors = append(report.Errors, path+": "+err.Error())
			} else {
				report.Worktrees = append(report.Worktrees, items...)
				for _, item := range items {
					if !item.Primary && item.Error == "" {
						registered[item.Path] = true
					}
					if item.Error != "" {
						report.Errors = append(report.Errors, item.Path+": "+item.Error)
					}
				}
			}
		}
	}
	completed := 0
	for index, path := range repositories {
		if ctx.Err() != nil {
			return report
		}
		update(Progress{Report: report, Completed: completed, Pending: len(roots) + len(repositories) - index, Path: path})
		inspect(path)
		completed++
	}
	var queue []string
	explicitRoots := make(map[string]bool)
	for _, root := range roots {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			continue
		}
		queue = append(queue, resolved)
		explicitRoots[resolved] = true
	}
	for index := 0; index < len(queue); index++ {
		if ctx.Err() != nil {
			return report
		}
		path := queue[index]
		update(Progress{Report: report, Completed: completed, Pending: len(queue) - index, Path: path})
		if !registered[path] || explicitRoots[path] {
			entries, err := os.ReadDir(path)
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
			} else {
				if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
					inspect(path)
				}
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					switch entry.Name() {
					case ".git", ".giga", "node_modules", "target", "vendor", ".venv", "venv", ".Trash":
						continue
					}
					queue = append(queue, filepath.Join(path, entry.Name()))
				}
			}
		}
		completed++
	}
	update(Progress{Report: report, Completed: completed, Done: true})
	return report
}

func DefaultRoots() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return []string{home}, nil
}
