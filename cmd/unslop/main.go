package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/executor"
	"github.com/yahn/unslop/internal/format"
	"github.com/yahn/unslop/internal/platform"
	"github.com/yahn/unslop/internal/scanner"
	"github.com/yahn/unslop/internal/ui"
)

type multimodFlag []string

func (m *multimodFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multimodFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fileArgs := args
	command, rest := splitCommand(args)
	original := command
	for {
		var next []string
		var code int
		switch command {
		case "repos", "worktrees":
			code = runWorktreesSubcommand(rest, stdout, stderr, &next)
		case "repo":
			return runRepoSubcommand(rest, stdout, stderr)
		case "files":
			code = runFiles(rest, stdin, stdout, stderr, &next)
		default:
			code = runFiles(args, stdin, stdout, stderr, &next)
		}
		command, _ = splitCommand(next)
		switch command {
		case "files":
			switch original {
			case "repos", "worktrees":
				args = next
			default:
				args = fileArgs
			}
		case "repos", "worktrees":
			switch original {
			case "repos", "worktrees":
				args = fileArgs
			default:
				args = next
			}
		default:
			return code
		}
		command, rest = splitCommand(args)
	}
}

func splitCommand(args []string) (string, []string) {
	if len(args) > 0 {
		return args[0], args[1:]
	}
	return "", nil
}

func runFiles(args []string, stdin io.Reader, stdout, stderr io.Writer, next *[]string) int {
	flags := flag.NewFlagSet("unslop", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: unslop [flags] | unslop repos [flags] | unslop worktrees [flags] | unslop repo [flags]")
		flags.PrintDefaults()
	}

	daysFlag := flags.Float64("days", 7.0, "Minimum inactivity days to qualify as unslop candidate")
	minDaysFlag := flags.Float64("min-days", 7.0, "Minimum inactivity days to qualify as unslop candidate")
	maxDaysFlag := flags.Float64("max-days", 0.0, "Maximum inactivity age in days (0 or negative for unlimited)")
	minSizeFlag := flags.Float64("min-size-mb", 0.0, "Minimum candidate size in MB")
	manifestFlag := flags.String("manifest", "", "Custom path to unslop manifest JSON")
	dryRunFlag := flags.Bool("dry-run", false, "Preview candidate scan without modifying files")
	applyFlag := flags.Bool("apply", false, "Execute staging and interactive prompt for candidate cleanup")
	applyDataFlag := flags.Bool("apply-data", false, "Explicit safety opt-in for user-data candidate deletion")
	includeDataFlag := flags.Bool("include-data", false, "Scan user-data directories")
	trashFlag := flags.Bool("trash", true, "Move to Trash (default: true)")
	forcePermanentFlag := flags.Bool("force-permanent", false, "Permanently delete without moving to Trash")
	recoverQuarantineFlag := flags.Bool("recover-quarantine", false, "Scan and restore orphaned quarantine entries")
	versionFlag := flags.Bool("version", false, "Print version information")

	var paths multimodFlag
	flags.Var(&paths, "path", "Explicit scan target root directories")

	var flagArgs []string
	var overrideArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "+") {
			overrideArgs = append(overrideArgs, arg)
			continue
		}

		if strings.HasPrefix(arg, "-") {
			rawName := strings.TrimLeft(arg, "-")
			name, _, hasValue := strings.Cut(rawName, "=")
			if name == "help" || name == "h" {
				flagArgs = append(flagArgs, arg)
				continue
			}
			if f := flags.Lookup(name); f != nil {
				flagArgs = append(flagArgs, arg)
				boolFlag, isBool := f.Value.(interface{ IsBoolFlag() bool })
				if !(isBool && boolFlag.IsBoolFlag()) && !hasValue && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.HasPrefix(args[i+1], "+") {
					i++
					flagArgs = append(flagArgs, args[i])
				}
				continue
			}

			overrideArgs = append(overrideArgs, arg)
			continue
		}

		overrideArgs = append(overrideArgs, arg)
	}

	if err := flags.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *daysFlag < 0 || *minDaysFlag < 0 {
		fmt.Fprintf(stderr, "Error: -min-days cannot be negative\n")
		return 2
	}

	if *minSizeFlag < 0 {
		fmt.Fprintf(stderr, "Error: -min-size-mb cannot be negative\n")
		return 2
	}

	if *versionFlag {
		fmt.Fprintf(stdout, "unslop version %s\n", config.Version)
		return 0
	}

	daysSet := false
	minDaysSet := false
	minSizeSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "days" {
			daysSet = true
		}
		if f.Name == "min-days" {
			minDaysSet = true
		}
		if f.Name == "min-size-mb" {
			minSizeSet = true
		}
	})

	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(stderr, "Error: scan path '%s' does not exist or is inaccessible: %v\n", p, err)
			return 1
		}
	}

	scanDirs := []string(paths)
	if len(scanDirs) == 0 {
		scanDirs = scanner.GetDefaultScanDirs()
	}

	if *recoverQuarantineFlag {
		cnt := executor.RecoverOrphanedQuarantines(scanDirs, stdout)
		fmt.Fprintf(stdout, "Quarantine recovery completed: %d items restored.\n", cnt)
		return 0
	}

	manifest, err := config.LoadManifest(*manifestFlag)
	if err != nil {
		fmt.Fprintf(stderr, "[FATAL] %v\n", err)
		return 1
	}

	engine := config.NewRuleEngine(manifest)
	allOverrides := append(overrideArgs, flags.Args()...)
	config.ApplyRuleOverrides(engine, allOverrides)

	diskTotal, diskUsed, diskFree, _ := platform.GetDiskSpace("/")
	dynamicMinSizeMB := config.CalculateDynamicMinSizeMB(diskTotal)

	minDays := *daysFlag
	if minDaysSet {
		minDays = *minDaysFlag
	} else if daysSet {
		minDays = *daysFlag
	} else if manifest.DefaultDays > 0 {
		minDays = manifest.DefaultDays
	}

	minSizeMB := *minSizeFlag
	if !minSizeSet {
		if manifest.DefaultMinSizeMB > 0 {
			minSizeMB = manifest.DefaultMinSizeMB
		} else {
			minSizeMB = dynamicMinSizeMB
		}
	}
	if minSizeMB <= 0 {
		minSizeMB = dynamicMinSizeMB
	}

	minSizeBytes := int64(minSizeMB * 1024 * 1024)

	fzfBin := ui.FindFzf()
	var candidates, selected []scanner.Candidate
	var scanErr error
	var worktreeTab bool
	if fzfBin != "" {
		selected, worktreeTab, scanErr = ui.ChooseFilesLive(fzfBin, diskTotal, diskUsed, diskFree, func(ctx context.Context, update func(scanner.Progress)) ([]scanner.Candidate, error) {
			var err error
			candidates, err = scanner.ScanLive(ctx, scanDirs, engine, minDays, *maxDaysFlag, minSizeBytes, *includeDataFlag, io.Discard, update)
			return candidates, err
		})
	} else {
		candidates, scanErr = scanner.ScanParallelChecked(scanDirs, engine, minDays, *maxDaysFlag, minSizeBytes, *includeDataFlag)
	}
	if scanErr != nil {
		fmt.Fprintf(stderr, "Error: %v. On macOS, check Files & Folders permissions for your terminal.\n", scanErr)
		if *applyFlag && !*dryRunFlag {
			return 1
		}
	}

	var totalCandidatesSizeBytes int64
	for _, c := range candidates {
		totalCandidatesSizeBytes += c.Size
	}

	if fzfBin == "" {
		if *applyFlag && !*dryRunFlag {
			fmt.Fprintln(stderr, "Error: -apply requires fzf for candidate selection. Install fzf or use -dry-run.")
			return 1
		}
		fmt.Fprintf(stderr, "\n[PLAN REPORT] fzf runtime binary not found. Standard text summary output below:\n\n")
		for index, c := range candidates {
			isNonDeletable := !c.CanDelete
			idTag := fmt.Sprintf("[%d]", index+1)
			paddedID := fmt.Sprintf("%-5s", idTag)

			fmt.Fprintf(stdout, " %s [%-14s | %-16s] %10s | %s | %s\n", paddedID, c.RiskClass, c.Category, format.FormatBytes(c.Size), format.FormatAgeDays(c.AgeDays), ui.CandidatePath(c, isNonDeletable))
		}
		fmt.Fprintf(stdout, "\nTotal candidates: %d (%s)\n", len(candidates), format.FormatBytes(totalCandidatesSizeBytes))
		if scanErr != nil {
			return 1
		}
		return 0
	}

	if worktreeTab {
		*next = []string{"repos"}
		for _, path := range paths {
			*next = append(*next, "-path", path)
		}
		return 0
	}

	isDryRun := *dryRunFlag || !*applyFlag
	useTrash := *trashFlag && !*forcePermanentFlag
	res := executor.ConfirmAndDeleteWithIO(selected, isDryRun, useTrash, *applyDataFlag, stdin, stdout, stderr, diskUsed, manifest)
	if len(res.Errors) > 0 || scanErr != nil {
		return 1
	}
	return 0
}
