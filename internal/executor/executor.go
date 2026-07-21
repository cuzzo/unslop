package executor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"path/filepath"

	"strings"
	"sync"
	"time"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/format"
	"github.com/yahn/unslop/internal/platform"
	"github.com/yahn/unslop/internal/scanner"
	"github.com/yahn/unslop/internal/ui"
)

type QuarantineJournalEntry struct {
	OpID           string    `json:"op_id"`
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path"`
	DeviceID       uint64    `json:"device_id,omitempty"`
	InodeNum       uint64    `json:"inode_num,omitempty"`
	HasIdentity    bool      `json:"has_identity,omitempty"`
	Phase          string    `json:"phase"`
	Timestamp      time.Time `json:"timestamp"`
}

type ExecutionResult struct {
	DeletedCount int
	DeletedBytes int64
	Skipped      int
	Errors       []string
}

var (
	journalMutex        sync.Mutex
	journalPathOverride string
)

func SetJournalPathOverride(path string) {
	journalMutex.Lock()
	defer journalMutex.Unlock()
	journalPathOverride = path
}

func getJournalPath() string {
	if journalPathOverride != "" {
		return journalPathOverride
	}
	if env := os.Getenv("UNSLOP_JOURNAL_PATH"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".unslop-journal.json"
	}
	return filepath.Join(home, ".unslop-journal.json")
}

func withJournalLock(jPath string, fn func() error) error {
	journalMutex.Lock()
	defer journalMutex.Unlock()

	dir := filepath.Dir(jPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for journal lock: %w", err)
	}

	lockPath := jPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open journal lockfile %s: %w", lockPath, err)
	}
	defer lockFile.Close()

	if err := platform.LockFile(lockFile); err != nil {
		return fmt.Errorf("failed to acquire exclusive journal lock on %s: %w", lockPath, err)
	}
	defer func() {
		_ = platform.UnlockFile(lockFile)
	}()

	return fn()
}

func loadJournalLocked(jPath string) ([]QuarantineJournalEntry, error) {
	if _, err := os.Stat(jPath); os.IsNotExist(err) {
		return []QuarantineJournalEntry{}, nil
	}

	data, err := os.ReadFile(jPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read journal file: %w", err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return []QuarantineJournalEntry{}, nil
	}

	var entries []QuarantineJournalEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("journal corrupted / failed to parse JSON at %s: %w", jPath, err)
	}

	return entries, nil
}

func saveJournalLocked(jPath string, entries []QuarantineJournalEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal journal: %w", err)
	}

	dir := filepath.Dir(jPath)
	if errMk := os.MkdirAll(dir, 0755); errMk != nil {
		return fmt.Errorf("failed to create journal directory: %w", errMk)
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d.%d", jPath, os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp journal file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp journal data: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to fsync temp journal data: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp journal file: %w", err)
	}

	if err := os.Rename(tmpPath, jPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to atomic rename journal file: %w", err)
	}

	if d, errDir := os.Open(dir); errDir == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return nil
}

func loadJournal(jPath string) ([]QuarantineJournalEntry, error) {
	var entries []QuarantineJournalEntry
	err := withJournalLock(jPath, func() error {
		var errLoad error
		entries, errLoad = loadJournalLocked(jPath)
		return errLoad
	})
	return entries, err
}

func recordQuarantineEntry(jPath string, entry QuarantineJournalEntry) error {
	return withJournalLock(jPath, func() error {
		entries, err := loadJournalLocked(jPath)
		if err != nil {
			return fmt.Errorf("cannot record journal entry because existing journal is corrupted or unreadable: %w", err)
		}
		entries = append(entries, entry)
		return saveJournalLocked(jPath, entries)
	})
}

func updateJournalEntryPhase(jPath string, opID string, phase string) error {
	return withJournalLock(jPath, func() error {
		entries, err := loadJournalLocked(jPath)
		if err != nil {
			return err
		}

		found := false
		for i := range entries {
			if entries[i].OpID == opID {
				entries[i].Phase = phase
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("journal entry for opID %s not found", opID)
		}

		return saveJournalLocked(jPath, entries)
	})
}

func removeJournalEntry(jPath string, opID string) error {
	return withJournalLock(jPath, func() error {
		entries, err := loadJournalLocked(jPath)
		if err != nil {
			return err
		}

		var updated []QuarantineJournalEntry
		for _, e := range entries {
			if e.OpID != opID {
				updated = append(updated, e)
			}
		}

		return saveJournalLocked(jPath, updated)
	})
}

func rollbackQuarantine(entry QuarantineJournalEntry) error {
	if entry.QuarantinePath == "" || entry.OriginalPath == "" {
		return errors.New("invalid journal entry paths for rollback")
	}

	if _, err := os.Lstat(entry.QuarantinePath); os.IsNotExist(err) {
		return nil
	}

	origPath := entry.OriginalPath
	if _, err := os.Lstat(origPath); err == nil {
		origPath = fmt.Sprintf("%s.restored-%d", entry.OriginalPath, time.Now().UnixNano())
	}

	origParent := filepath.Dir(origPath)
	if err := os.MkdirAll(origParent, 0755); err != nil {
		return fmt.Errorf("failed to create original parent directory during rollback: %w", err)
	}

	if err := movePath(entry.QuarantinePath, origPath); err != nil {
		return fmt.Errorf("failed to restore %s to %s: %w", entry.QuarantinePath, origPath, err)
	}

	return nil
}

func RecoverOrphanedQuarantines(scanDirs []string, out io.Writer) int {
	jPath := getJournalPath()
	entries, err := loadJournal(jPath)
	if err == nil && len(entries) > 0 {
		var activeEntries []QuarantineJournalEntry
		for _, entry := range entries {
			if entry.Phase != "completed" {
				if errRB := rollbackQuarantine(entry); errRB != nil {
					fmt.Fprintf(out, "[JOURNAL RECOVERY WARNING] Failed to rollback %s: %v\n", entry.QuarantinePath, errRB)
					activeEntries = append(activeEntries, entry)
				}
			}
		}
		_ = withJournalLock(jPath, func() error {
			return saveJournalLocked(jPath, activeEntries)
		})
	}

	count := 0
	for _, root := range scanDirs {
		p := root
		if strings.HasPrefix(root, "~") {
			home, _ := os.UserHomeDir()
			p = filepath.Join(home, root[1:])
		}
		p = filepath.Clean(p)

		_ = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && strings.Contains(d.Name(), ".unslop-quarantine-") {
				parent := filepath.Dir(path)
				baseName := d.Name()
				origName := baseName
				if idx := strings.Index(baseName, ".unslop-quarantine-"); idx != -1 {
					origName = baseName[:idx]
				}
				targetPath := filepath.Join(parent, origName)
				if _, err := os.Lstat(targetPath); os.IsNotExist(err) {
					if errMove := movePath(path, targetPath); errMove == nil {
						count++
						fmt.Fprintf(out, "[ORPHAN RECOVERY] Restored orphaned quarantine %s -> %s\n", path, targetPath)
					}
				}
				return filepath.SkipDir
			}
			return nil
		})
	}
	return count
}

func movePath(src, dst string) error {
	return os.Rename(src, dst)
}

func findUniqueTrashDest(filesDir, origName string) (string, string) {
	ext := filepath.Ext(origName)
	stem := strings.TrimSuffix(origName, ext)

	candidateName := origName
	candidatePath := filepath.Join(filesDir, candidateName)

	counter := 1
	for {
		if _, err := os.Lstat(candidatePath); os.IsNotExist(err) {
			return candidateName, candidatePath
		}
		candidateName = fmt.Sprintf("%s.%d%s", stem, counter, ext)
		candidatePath = filepath.Join(filesDir, candidateName)
		counter++
	}
}

func createTrashInfo(infoDir, trashName, origPath string) (string, error) {
	infoPath := filepath.Join(infoDir, trashName+".trashinfo")
	content := fmt.Sprintf("[Trash Info]\nPath=%s\nDeletionDate=%s\n",
		origPath, time.Now().Format("2006-01-02T15:04:05"))

	err := os.WriteFile(infoPath, []byte(content), 0600)
	if err != nil {
		return "", fmt.Errorf("failed to write .trashinfo metadata at %s: %w", infoPath, err)
	}
	return infoPath, nil
}

func moveToTrash(path string) error {
	home, errHome := os.UserHomeDir()
	if errHome == nil && home != "" {
		trashDir := filepath.Join(home, ".local", "share", "Trash")
		filesDir := filepath.Join(trashDir, "files")
		infoDir := filepath.Join(trashDir, "info")

		if errMk := os.MkdirAll(filesDir, 0700); errMk == nil {
			if errMkInfo := os.MkdirAll(infoDir, 0700); errMkInfo == nil {
				origName := filepath.Base(path)
				trashName, trashPath := findUniqueTrashDest(filesDir, origName)

				infoPath, errInfo := createTrashInfo(infoDir, trashName, path)
				if errInfo == nil {
					if errRename := os.Rename(path, trashPath); errRename == nil {
						return nil
					}
					_ = os.Remove(infoPath)
				}
			}
		}
	}

	return platform.MoveToTrashOS(path)
}

func ConfirmAndDeleteWithIO(selected []scanner.Candidate, dryRun bool, useTrash bool, allowData bool, stdin io.Reader, stdout, stderr io.Writer, diskTotal, diskUsed, diskFree uint64, manifest config.Manifest) ExecutionResult {
	res := ExecutionResult{}
	if len(selected) == 0 {
		fmt.Fprintln(stdout, "No items selected. Exiting.")
		return res
	}

	engine := config.NewRuleEngine(manifest)
	pkgInventory := scanner.LoadPackageInventory()

	var actionable []scanner.Candidate
	var reportOnly []scanner.Candidate

	for _, c := range selected {
		rule, _, _ := engine.MatchDir(filepath.Base(c.Path), c.Path, pkgInventory.CargoPkgs)
		if rule == nil {
			fi, errStat := os.Lstat(c.Path)
			if errStat == nil {
				rule, _, _ = engine.MatchFile(filepath.Base(c.Path), c.Path, fi, pkgInventory.CargoPkgs)
			}
		}
		if rule == nil {
			rule = &config.Rule{
				ID:        c.RuleID,
				Category:  c.Category,
				RiskClass: c.RiskClass,
			}
		}

		authAction, canDel := c.ProposedAction, c.CanDelete
		if rule != nil {
			authAction, canDel = c.ProposedAction, c.CanDelete
		}

		if !canDel || authAction == "report-only" {
			reportOnly = append(reportOnly, c)
		} else {
			actionable = append(actionable, c)
		}
	}

	var totalActionable int64
	for _, c := range actionable {
		totalActionable += c.Size
	}

	newDiskUsed := uint64(0)
	if diskUsed > uint64(totalActionable) {
		newDiskUsed = diskUsed - uint64(totalActionable)
	}

	if len(actionable) > 0 {
		fmt.Fprintf(stdout, "\n============================================================\n")
		fmt.Fprintf(stdout, " STAGED FOR REVIEW: %d items (%s)\n", len(actionable), ui.FormatBytes(totalActionable))
		if useTrash {
			fmt.Fprintf(stdout, " DISK SAVINGS: Move to Trash (%s staged; use -force-permanent to reclaim space)\n", ui.FormatBytes(totalActionable))
		} else {
			fmt.Fprintf(stdout, " DISK SAVINGS: %s used -> %s used (Will free %s)\n",
				ui.FormatUintBytes(diskUsed), ui.FormatUintBytes(newDiskUsed), ui.FormatBytes(totalActionable))
		}
		fmt.Fprintf(stdout, "============================================================\n")
		for _, c := range actionable {
			kind := "FILE"
			if c.IsDir {
				kind = "DIR "
			}
			abbrevPath := format.AbbreviateHomePath(c.Path)
			pathTag := abbrevPath
			if c.IsGitIgnored {
				pathTag = "[GITIGNORE] " + abbrevPath
			}
			statusTag := ""
			if c.RiskClass == config.RiskUserData {
				statusTag = " [REQUIRES -apply-data]"
			}
			fmt.Fprintf(stdout, " [%s: %-13s | RISK: %-16s] %10s | %s old | %s%s\n", kind, c.Category, c.RiskClass, ui.FormatBytes(c.Size), format.FormatAgeDays(c.AgeDays), pathTag, statusTag)
		}
		fmt.Fprintf(stdout, "============================================================\n")
	}

	if len(reportOnly) > 0 {
		var totalReportOnly int64
		for _, c := range reportOnly {
			totalReportOnly += c.Size
		}
		fmt.Fprintf(stdout, "\n============================================================\n")
		fmt.Fprintf(stdout, " REPORT-ONLY / INFORMATIONAL (No Deletion Staged): %d items (%s)\n", len(reportOnly), ui.FormatBytes(totalReportOnly))
		fmt.Fprintf(stdout, "============================================================\n")
		for _, c := range reportOnly {
			kind := "FILE"
			if c.IsDir {
				kind = "DIR "
			}
			abbrevPath := format.AbbreviateHomePath(c.Path)
			var tags []string
			tags = append(tags, "[CANNOT DELETE]")
			if c.IsGitIgnored {
				tags = append(tags, "[GITIGNORE]")
			}
			pathStr := strings.Join(tags, " ") + " " + abbrevPath
			fmt.Fprintf(stdout, " [%s: %-13s | RISK: %-16s] %10s | %s old | %s [REPORT-ONLY]\n", kind, c.Category, c.RiskClass, ui.FormatBytes(c.Size), format.FormatAgeDays(c.AgeDays), pathStr)
		}
		fmt.Fprintf(stdout, "============================================================\n")
	}

	if dryRun {
		fmt.Fprintln(stdout, "\n[READ-ONLY PLAN MODE] No files were deleted. Pass '-apply' flag to execute deletion.")
		res.Skipped = len(selected)
		return res
	}

	if len(actionable) == 0 {
		fmt.Fprintln(stdout, "\nNo actionable items eligible for deletion. Exiting.")
		res.Skipped = len(selected)
		return res
	}

	fmt.Fprintf(stdout, "\nAre you sure you want to proceed with permanent action on these %d items? (y/N): ", len(actionable))
	reader := bufio.NewReader(stdin)
	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) != "y" {
		fmt.Fprintln(stdout, "Operation cancelled.")
		res.Skipped = len(selected)
		return res
	}

	fmt.Fprintln(stdout, "\nExecuting actions...")
	jPath := getJournalPath()

	for _, c := range actionable {
		rule, _, uninstallArgs := engine.MatchDir(filepath.Base(c.Path), c.Path, pkgInventory.CargoPkgs)
		if rule == nil {
			fi, errStat := os.Lstat(c.Path)
			if errStat == nil {
				rule, _, uninstallArgs = engine.MatchFile(filepath.Base(c.Path), c.Path, fi, pkgInventory.CargoPkgs)
			}
		}

		hasProtected := platform.ContainsProtectedPath(c.Path)
		authAction, canDel := c.ProposedAction, c.CanDelete
		if rule != nil {
			authAction, canDel = c.ProposedAction, c.CanDelete
		}

		if hasProtected || !canDel || authAction == "report-only" {
			fmt.Fprintf(stdout, " [PROTECTED SAFEGUARD] %s contains protected credential/config files inside. Refusing deletion!\n", c.Path)
			res.Skipped++
			continue
		}

		hasBoundary, boundaryPath, bErr := platform.ContainsMountOrReparsePoint(c.Path)
		if hasBoundary {
			fmt.Fprintf(stdout, " [MOUNT SAFEGUARD] %s contains mount point/reparse boundary at %s (%v). Refusing deletion!\n", c.Path, boundaryPath, bErr)
			res.Skipped++
			continue
		}

		fiNow, errLstat := os.Lstat(c.Path)
		if errLstat != nil {
			fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s no longer exists on disk: %v. Skipping.\n", c.Path, errLstat)
			res.Skipped++
			continue
		}

		if c.IsDir {
			sz, maxModTime, _, _, errInsp := inspectSubtreeForRevalidation(c.Path)
			if errInsp != nil {
				fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s unreadable subtree during revalidation: %v. Skipping.\n", c.Path, errInsp)
				res.Skipped++
				continue
			}
			if sz != c.Size {
				fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s size changed from %s to %s during scan window. Aborting deletion!\n",
					c.Path, ui.FormatBytes(c.Size), ui.FormatBytes(sz))
				res.Skipped++
				continue
			}
			if maxModTime.After(c.ModTime) {
				fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s modified since scan (new activity at %s vs scan time %s). Aborting deletion!\n",
					c.Path, maxModTime.Format("15:04:05"), c.ModTime.Format("15:04:05"))
				res.Skipped++
				continue
			}
			if !c.RootModTime.IsZero() && fiNow.ModTime().After(c.RootModTime) {
				fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s root modified since scan. Aborting deletion!\n", c.Path)
				res.Skipped++
				continue
			}
		} else {
			if fiNow.Size() != c.Size {
				fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s size changed from %s to %s. Aborting!\n", c.Path, ui.FormatBytes(c.Size), ui.FormatBytes(fiNow.Size()))
				res.Skipped++
				continue
			}
			effTime := scanner.GetEffectiveItemTime(fiNow)
			if effTime.After(c.ModTime) {
				fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s accessed/modified since scan. Aborting!\n", c.Path)
				res.Skipped++
				continue
			}
		}

		devNow, inoNow, hasIdNow := platform.GetFileIdentity(c.Path, fiNow)
		if c.HasIdentity && hasIdNow {
			if devNow != c.DeviceID || inoNow != c.InodeNum {
				fmt.Fprintf(stdout, " [REVALIDATION FAILURE] %s object identity mutated since scan (Device/Inode %d/%d -> %d/%d). Replacement race detected! Aborting deletion!\n",
					c.Path, c.DeviceID, c.InodeNum, devNow, inoNow)
				res.Skipped++
				continue
			}
		}

		opID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(c.Path))
		parentDir := filepath.Dir(c.Path)
		quarantineName := fmt.Sprintf("%s.unslop-quarantine-%s", filepath.Base(c.Path), opID)
		quarantinePath := filepath.Join(parentDir, quarantineName)

		entry := QuarantineJournalEntry{
			OpID:           opID,
			OriginalPath:   c.Path,
			QuarantinePath: quarantinePath,
			DeviceID:       devNow,
			InodeNum:       inoNow,
			HasIdentity:    hasIdNow,
			Phase:          "isolated",
			Timestamp:      time.Now(),
		}

		if errJournal := recordQuarantineEntry(jPath, entry); errJournal != nil {
			fmt.Fprintf(stderr, " [TRANSACTION FAILURE] Failed to write journal entry for %s: %v. Aborting deletion!\n", c.Path, errJournal)
			res.Errors = append(res.Errors, fmt.Sprintf("Journal write failed for %s", c.Path))
			res.Skipped++
			continue
		}

		if errMove := movePath(c.Path, quarantinePath); errMove != nil {
			fmt.Fprintf(stderr, " [QUARANTINE FAILURE] Failed to isolate %s into quarantine %s: %v. Aborting!\n", c.Path, quarantinePath, errMove)
			_ = removeJournalEntry(jPath, opID)
			res.Errors = append(res.Errors, fmt.Sprintf("Quarantine isolate failed for %s", c.Path))
			res.Skipped++
			continue
		}

		if authAction == "uninstall_package" && len(uninstallArgs) > 0 {
			cmdName := uninstallArgs[0]
			cmdArgs := uninstallArgs[1:]
			fmt.Fprintf(stdout, " [UNINSTALL PACKAGE] Running %s...\n", strings.Join(uninstallArgs, " "))
			cmd := exec.Command(cmdName, cmdArgs...)
			var errBuf bytes.Buffer
			cmd.Stderr = &errBuf
			if errRun := cmd.Run(); errRun != nil {
				fmt.Fprintf(stderr, " [UNINSTALL FAILURE] Package manager command failed: %v. Output: %s. Rolling back quarantine...\n", errRun, errBuf.String())
				if errRB := rollbackQuarantine(entry); errRB != nil {
					fmt.Fprintf(stderr, " [ROLLBACK CRITICAL] Rollback failed for %s: %v!\n", c.Path, errRB)
				} else {
					_ = removeJournalEntry(jPath, opID)
				}
				res.Errors = append(res.Errors, fmt.Sprintf("Package uninstall failed for %s", c.Path))
				res.Skipped++
				continue
			}

			_ = updateJournalEntryPhase(jPath, opID, "completed")
			_ = os.RemoveAll(quarantinePath)
			_ = removeJournalEntry(jPath, opID)
			res.DeletedCount++
			res.DeletedBytes += c.Size
			fmt.Fprintf(stdout, " [SUCCESS] Uninstalled %s and removed %s (%s freed)\n", c.PackageName, c.Path, ui.FormatBytes(c.Size))
			continue
		}

		if useTrash {
			if errTrash := moveToTrash(quarantinePath); errTrash != nil {
				fmt.Fprintf(stderr, " [TRASH FAILURE] Trash failed for %s: %v. Rolling back quarantine...\n", c.Path, errTrash)
				if errRB := rollbackQuarantine(entry); errRB != nil {
					fmt.Fprintf(stderr, " [ROLLBACK CRITICAL] Rollback failed for %s: %v!\n", c.Path, errRB)
				} else {
					_ = removeJournalEntry(jPath, opID)
				}
				res.Errors = append(res.Errors, fmt.Sprintf("Trash move failed for %s", c.Path))
				res.Skipped++
				continue
			}
			_ = updateJournalEntryPhase(jPath, opID, "completed")
			_ = removeJournalEntry(jPath, opID)
			res.DeletedCount++
			res.DeletedBytes += c.Size
			fmt.Fprintf(stdout, " [SUCCESS] Moved to Trash: %s (%s)\n", c.Path, ui.FormatBytes(c.Size))
		} else {
			if errRemove := os.RemoveAll(quarantinePath); errRemove != nil {
				fmt.Fprintf(stderr, " [DELETE FAILURE] Deletion failed for %s: %v. Rolling back quarantine...\n", c.Path, errRemove)
				if errRB := rollbackQuarantine(entry); errRB != nil {
					fmt.Fprintf(stderr, " [ROLLBACK CRITICAL] Rollback failed for %s: %v!\n", c.Path, errRB)
				} else {
					_ = removeJournalEntry(jPath, opID)
				}
				res.Errors = append(res.Errors, fmt.Sprintf("RemoveAll failed for %s", c.Path))
				res.Skipped++
				continue
			}
			_ = updateJournalEntryPhase(jPath, opID, "completed")
			_ = removeJournalEntry(jPath, opID)
			res.DeletedCount++
			res.DeletedBytes += c.Size
			fmt.Fprintf(stdout, " [SUCCESS] Permanently deleted %s (%s freed)\n", c.Path, ui.FormatBytes(c.Size))
		}
	}

	return res
}

func inspectSubtreeForRevalidation(dirPath string) (size int64, maxModTime time.Time, fileCount int64, hasProtected bool, err error) {
	fi, errLstat := os.Lstat(dirPath)
	if errLstat != nil {
		return 0, time.Now(), 0, true, errLstat
	}
	maxModTime = fi.ModTime()

	var walkErr error
	errWalk := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			walkErr = err
			return filepath.SkipAll
		}
		if platform.IsProtected(path) {
			hasProtected = true
		}

		fileCount++
		info, errInfo := d.Info()
		if errInfo != nil {
			return nil
		}

		size += info.Size()
		effTime := scanner.GetEffectiveItemTime(info)
		if effTime.After(maxModTime) {
			maxModTime = effTime
		}
		return nil
	})

	if errWalk != nil && walkErr == nil {
		walkErr = errWalk
	}

	return size, maxModTime, fileCount, hasProtected, walkErr
}
