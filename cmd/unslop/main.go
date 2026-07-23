package main

import (
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
	flags := flag.NewFlagSet("unslop", flag.ContinueOnError)
	flags.SetOutput(stderr)

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

	knownFlagsWithValue := map[string]bool{
		"days":        true,
		"min-days":    true,
		"max-days":    true,
		"min-size-mb": true,
		"manifest":    true,
		"path":        true,
	}
	knownBoolFlags := map[string]bool{
		"dry-run":            true,
		"apply":              true,
		"apply-data":         true,
		"include-data":       true,
		"trash":              true,
		"force-permanent":    true,
		"recover-quarantine": true,
		"version":            true,
		"help":               true,
		"h":                  true,
	}

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
			name := rawName
			if idx := strings.Index(rawName, "="); idx != -1 {
				name = rawName[:idx]
			}

			if knownBoolFlags[name] {
				flagArgs = append(flagArgs, arg)
				continue
			}
			if knownFlagsWithValue[name] {
				flagArgs = append(flagArgs, arg)
				if !strings.Contains(rawName, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.HasPrefix(args[i+1], "+") {
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

	candidates := scanner.ScanParallel(scanDirs, engine, minDays, *maxDaysFlag, minSizeBytes, *includeDataFlag)

	var totalCandidatesSizeBytes int64
	for _, c := range candidates {
		totalCandidatesSizeBytes += c.Size
	}

	fzfBin := ui.FindFzf()
	if fzfBin == "" {
		fmt.Fprintf(stderr, "\n[PLAN REPORT] fzf runtime binary not found. Standard text summary output below:\n\n")
		for _, c := range candidates {
			isNonDeletable := !c.CanDelete || c.ProposedAction == "report-only"
			idTag := fmt.Sprintf("[%d]", c.ID)
			paddedID := fmt.Sprintf("%-5s", idTag)

			abbrevPath := format.AbbreviateHomePath(c.Path)
			var tags []string
			if isNonDeletable {
				tags = append(tags, "[CANNOT DELETE]")
			}
			if c.IsGitIgnored {
				tags = append(tags, "[GITIGNORE]")
			}
			if c.IsDevBinary {
				tags = append(tags, "[DEV BINARY]")
			}
			pathStr := abbrevPath
			if len(tags) > 0 {
				pathStr = strings.Join(tags, " ") + " " + abbrevPath
			}
			fmt.Fprintf(stdout, " %s [%-14s | %-16s] %10s | %s | %s\n", paddedID, c.RiskClass, c.Category, ui.FormatBytes(c.Size), format.FormatAgeDays(c.AgeDays), pathStr)
		}
		fmt.Fprintf(stdout, "\nTotal candidates: %d (%s)\n", len(candidates), ui.FormatBytes(totalCandidatesSizeBytes))
		return 0
	}

	selected := ui.RunFzfInteractive(candidates, fzfBin, diskTotal, diskUsed, diskFree)

	isDryRun := *dryRunFlag || !*applyFlag
	useTrash := *trashFlag && !*forcePermanentFlag
	res := executor.ConfirmAndDeleteWithIO(selected, isDryRun, useTrash, *applyDataFlag, stdin, stdout, stderr, diskTotal, diskUsed, diskFree, manifest)
	if len(res.Errors) > 0 {
		return 1
	}
	return 0
}
