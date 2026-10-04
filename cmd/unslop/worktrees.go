package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/yahn/unslop/internal/ui"
	"github.com/yahn/unslop/internal/worktree"
)

func runWorktreesSubcommand(args []string, stdout, stderr io.Writer, next *[]string) int {
	flags := flag.NewFlagSet("unslop repos", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var paths multimodFlag
	var repositories multimodFlag
	flags.Var(&paths, "path", "Search root; repeat for additional roots (default: home)")
	flags.Var(&repositories, "repo", "Inspect only this repository's registered worktrees; repeat for additional repositories")
	jsonFlag := flags.Bool("json", false, "Print worktree and outstanding commit evidence as JSON")
	textFlag := flags.Bool("non-interactive", false, "Print the report without opening the Repos tab")
	days := flags.Int("days", 14, "Show distinct branch commits in the last N days")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	paths = append(paths, flags.Args()...)
	if *days <= 0 {
		fmt.Fprintln(stderr, "-days must be positive")
		return 2
	}
	if len(paths) == 0 && len(repositories) == 0 {
		roots, err := worktree.DefaultRoots()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		paths = roots
	}
	fzf := ui.FindFzf()
	interactive := fzf != "" && !*jsonFlag && !*textFlag
	var report worktree.Report
	if !interactive {
		report = worktree.Discover(paths, repositories, stderr)
		var analysed []worktree.Worktree
		for _, group := range worktree.Groups(report.Worktrees) {
			project := worktree.AnalyzeProject(context.Background(), group, *days)
			report.Projects = append(report.Projects, project)
			report.Errors = append(report.Errors, project.Errors...)
			analysed = append(analysed, project.Worktrees...)
		}
		report.Worktrees = analysed
	}
	if *jsonFlag {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	} else {
		if interactive {
			for {
				selected, filesTab, discovered, err := worktree.ChooseLive(paths, repositories, fzf, stderr)
				report = discovered
				back := false
				if err == nil && !filesTab && len(selected) > 0 {
					_, filesTab, back, err = worktree.ChooseProjectLive(selected, *days, fzf, stderr)
				}
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				if filesTab {
					*next = []string{"files"}
					for _, path := range report.Roots {
						*next = append(*next, "-path", path)
					}
					return 0
				}
				if !back {
					break
				}
			}
		} else {
			for _, project := range report.Projects {
				worktree.PrintProject(project, stdout)
			}
		}
	}
	for _, err := range report.Errors {
		fmt.Fprintln(stderr, ui.SanitizeTerminalString(err))
	}
	if len(report.Errors) > 0 {
		return 1
	}
	return 0
}
