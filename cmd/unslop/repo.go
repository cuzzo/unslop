package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/yahn/unslop/internal/repo"
	"github.com/yahn/unslop/internal/ui"
)

func runRepoSubcommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("unslop repo", flag.ContinueOnError)
	flags.SetOutput(stderr)

	minSizeMBFlag := flags.Float64("min-size-mb", 0.5, "Minimum candidate size in MB to include (default: 0.5)")
	minSizeFlag := flags.Float64("min-size", 0.5, "Minimum candidate size in MB to include (default: 0.5)")
	outputFlag := flags.String("output", "unslop-git-filter.txt", "Output filter manifest file for git-filter-repo")
	nonInteractiveFlag := flags.Bool("non-interactive", false, "Run in non-interactive mode selecting all candidates")
	dryRunFlag := flags.Bool("dry-run", false, "Preview history scan without writing manifest file")
	jsonFlag := flags.Bool("json", false, "Output history bloat scan results as JSON")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	chosenMinSize := 0.5
	minSizeSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "min-size" {
			chosenMinSize = *minSizeFlag
			minSizeSet = true
		} else if f.Name == "min-size-mb" && !minSizeSet {
			chosenMinSize = *minSizeMBFlag
		}
	})

	repoPath := "."
	if flags.NArg() > 0 {
		repoPath = flags.Arg(0)
	}

	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error resolving path '%s': %v\n", repoPath, err)
		return 1
	}

	analyzer := repo.NewGitAnalyzer()
	if !analyzer.Detect(absPath) {
		fmt.Fprintf(stderr, "Error: directory '%s' is not a valid Git repository.\n", absPath)
		return 1
	}

	opts := repo.ScanOptions{
		MinSizeMB:      chosenMinSize,
		NonInteractive: *nonInteractiveFlag,
		OutputFile:     *outputFlag,
		Stderr:         stderr,
	}

	candidates, err := analyzer.AnalyzeHistory(absPath, opts)
	if err != nil {
		fmt.Fprintf(stderr, "Error scanning Git history: %v\n", err)
		return 1
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(candidates); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON output: %v\n", err)
			return 1
		}
		return 0
	}

	fzfBin := ui.FindFzf()
	selected := repo.RunRepoUI(candidates, fzfBin, *nonInteractiveFlag, stdout, stderr)

	if len(selected) == 0 {
		fmt.Fprintln(stdout, "No candidates selected.")
		return 0
	}

	var selectedSizeBytes int64
	for _, c := range selected {
		selectedSizeBytes += c.Size
	}

	if *dryRunFlag {
		fmt.Fprintf(stdout, "\n[DRY RUN] Would write %d filter rules (%s) to %s\n", len(selected), repo.FormatInstructions(*outputFlag, len(selected), selectedSizeBytes), *outputFlag)
		return 0
	}

	outputPath := *outputFlag
	if !filepath.IsAbs(outputPath) {
		outputPath = filepath.Join(absPath, outputPath)
	}

	if err := repo.WriteFilterManifest(selected, outputPath); err != nil {
		fmt.Fprintf(stderr, "Error writing filter manifest: %v\n", err)
		return 1
	}

	instructions := repo.FormatInstructions(outputPath, len(selected), selectedSizeBytes)
	fmt.Fprintln(stdout, instructions)

	return 0
}
