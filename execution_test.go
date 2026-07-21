package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestQuarantineArchitectureAndRollback(t *testing.T) {
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "quarantine_target")
	os.MkdirAll(targetDir, 0755)

	// Create file inside candidate directory
	os.WriteFile(filepath.Join(targetDir, "data.txt"), []byte("data"), 0644)
	info, _ := os.Lstat(targetDir)
	sz, maxModTime, fCount, _ := getDirStats(targetDir, time.Now())

	c := Candidate{
		ID:             1,
		Path:           targetDir,
		Size:           sz,
		FileCount:      fCount,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		RootModTime:    info.ModTime(),
		ModTime:        maxModTime,
	}

	var stdout bytes.Buffer
	stdin := strings.NewReader("y\n")

	// Execute deletion using quarantine path (force-permanent deletion mode)
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, false, 1000, 1000, &stdout, stdin)

	if res.Completed != 1 || res.Failed != 0 || res.Aborted != 0 {
		t.Errorf("Expected 1 completed deletion via quarantine; got completed=%d, failed=%d, aborted=%d", res.Completed, res.Failed, res.Aborted)
	}

	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Errorf("Target directory %s was not deleted after quarantine execution", targetDir)
	}
}

func TestRevalidationNestedFileAdded(t *testing.T) {
	tmpDir := t.TempDir()
	candDir := filepath.Join(tmpDir, "cand_dir_added")
	os.MkdirAll(candDir, 0755)
	os.WriteFile(filepath.Join(candDir, "initial.txt"), []byte("initial"), 0644)

	info, _ := os.Lstat(candDir)
	sz, maxModTime, fCount, _ := getDirStats(candDir, time.Now())

	// Simulate adding a nested file AFTER scan
	os.WriteFile(filepath.Join(candDir, "added_after_scan.txt"), []byte("new file"), 0644)

	c := Candidate{
		ID:             2,
		Path:           candDir,
		Size:           sz,
		FileCount:      fCount, // Recorded before nested file was added
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		RootModTime:    info.ModTime(),
		ModTime:        maxModTime,
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if res.Aborted != 1 || res.Completed != 0 {
		t.Errorf("Expected 1 aborted action when nested file is added; got aborted=%d, completed=%d", res.Aborted, res.Completed)
	}
	out := stdout.String()
	if !strings.Contains(out, "[ABORT] File count changed") && !strings.Contains(out, "[ABORT] Root modification time changed") {
		t.Errorf("Expected ABORT File count or RootModTime changed message; got:\n%s", out)
	}
	if _, err := os.Stat(candDir); os.IsNotExist(err) {
		t.Errorf("Candidate directory %s was deleted instead of rolled back!", candDir)
	}
}

func TestRevalidationNestedFileModifiedWithoutRootTimestampChange(t *testing.T) {
	tmpDir := t.TempDir()
	candDir := filepath.Join(tmpDir, "cand_dir_mod")
	os.MkdirAll(candDir, 0755)
	childFile := filepath.Join(candDir, "child.txt")
	os.WriteFile(childFile, []byte("data"), 0644)

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(candDir, oldTime, oldTime)
	os.Chtimes(childFile, oldTime, oldTime)

	info, _ := os.Lstat(candDir)
	sz, _, fCount, _ := getDirStats(candDir, time.Now())

	// Modify child file timestamp without touching root directory container timestamp
	newerTime := time.Now().Add(-1 * 24 * time.Hour)
	os.Chtimes(childFile, newerTime, newerTime)

	c := Candidate{
		ID:             3,
		Path:           candDir,
		Size:           sz,
		FileCount:      fCount,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		RootModTime:    info.ModTime(),
		ModTime:        oldTime, // Recorded old subtree modtime
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if res.Aborted != 1 || res.Completed != 0 {
		t.Errorf("Expected 1 aborted action when nested file timestamp changes; got aborted=%d, completed=%d", res.Aborted, res.Completed)
	}
	if !strings.Contains(stdout.String(), "[ABORT] Subtree newest modification time changed") {
		t.Errorf("Expected ABORT Subtree newest modification time changed message; got:\n%s", stdout.String())
	}
	if _, err := os.Stat(candDir); os.IsNotExist(err) {
		t.Errorf("Candidate directory %s was deleted instead of rolled back!", candDir)
	}
}

func TestRevalidationSizeChanged(t *testing.T) {
	tmpDir := t.TempDir()
	candDir := filepath.Join(tmpDir, "cand_dir_size")
	os.MkdirAll(candDir, 0755)
	childFile := filepath.Join(candDir, "child.txt")
	os.WriteFile(childFile, []byte("data"), 0644)

	info, _ := os.Lstat(candDir)
	sz, maxModTime, _, _ := getDirStats(candDir, time.Now())

	// Overwrite child file with larger payload after scan
	os.WriteFile(childFile, []byte(strings.Repeat("X", 1000)), 0644)
	_, _, fCountNew, _ := getDirStats(candDir, time.Now())

	c := Candidate{
		ID:             4,
		Path:           candDir,
		Size:           sz,
		FileCount:      fCountNew, // Keep file count same, but size differs
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		RootModTime:    info.ModTime(),
		ModTime:        maxModTime,
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if res.Aborted != 1 || res.Completed != 0 {
		t.Errorf("Expected 1 aborted action when size changes; got aborted=%d, completed=%d", res.Aborted, res.Completed)
	}
	if !strings.Contains(stdout.String(), "[ABORT] Subtree size changed") {
		t.Errorf("Expected ABORT Subtree size changed message; got:\n%s", stdout.String())
	}
	if _, err := os.Stat(candDir); os.IsNotExist(err) {
		t.Errorf("Candidate directory %s was deleted instead of rolled back!", candDir)
	}
}

func TestRootModTimeRevalidationAbort(t *testing.T) {
	tmpDir := t.TempDir()
	candDir := filepath.Join(tmpDir, "root_mod_time_changed")
	os.MkdirAll(candDir, 0755)
	os.WriteFile(filepath.Join(candDir, "child.txt"), []byte("data"), 0644)

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(candDir, oldTime, oldTime)
	info, _ := os.Lstat(candDir)
	sz, maxModTime, fCount, _ := getDirStats(candDir, time.Now())

	// Touch root directory container timestamp before execution
	newerTime := time.Now().Add(-1 * 24 * time.Hour)
	os.Chtimes(candDir, newerTime, newerTime)

	c := Candidate{
		ID:             50,
		Path:           candDir,
		Size:           sz,
		FileCount:      fCount,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		RootModTime:    info.ModTime(), // Old recorded root modtime
		ModTime:        maxModTime,
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if res.Aborted != 1 || res.Completed != 0 {
		t.Errorf("Expected 1 aborted action when RootModTime changes; got aborted=%d, completed=%d", res.Aborted, res.Completed)
	}
	if !strings.Contains(stdout.String(), "[ABORT] Root modification time changed") {
		t.Errorf("Expected ABORT Root modification time changed message; got:\n%s", stdout.String())
	}
}

func TestUninstallPackageEmptyArgsRefused(t *testing.T) {
	tmpDir := t.TempDir()
	dummyPkg := filepath.Join(tmpDir, "dummy-empty-args")
	os.WriteFile(dummyPkg, []byte("pkg"), 0644)

	cand := Candidate{
		ID:             51,
		Path:           dummyPkg,
		Size:           3,
		RiskClass:      RiskPackageManaged,
		UninstallArgs:  nil, // Empty args
		CanDelete:      false,
		ProposedAction: "report-only",
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if res.Skipped != 1 || res.Completed != 0 {
		t.Errorf("Expected skipped action for package-managed candidate; got skipped=%d, completed=%d", res.Skipped, res.Completed)
	}
	if !strings.Contains(strings.ToLower(stdout.String()), "action refused") && !strings.Contains(strings.ToLower(stdout.String()), "report-only") {
		t.Errorf("Expected Action refused print; got:\n%s", stdout.String())
	}
}

func TestRollbackQuarantineFailureHandling(t *testing.T) {
	tmpDir := t.TempDir()
	origDir := filepath.Join(tmpDir, "orig_occupied")
	qDir := filepath.Join(tmpDir, "quarantine_dir")

	os.MkdirAll(origDir, 0755)
	os.WriteFile(filepath.Join(origDir, "file1.txt"), []byte("data1"), 0644)

	os.MkdirAll(qDir, 0755)
	os.WriteFile(filepath.Join(qDir, "file2.txt"), []byte("data2"), 0644)

	var buf bytes.Buffer
	// Rollback when original path is occupied must not overwrite origDir, but restore qDir to collision-safe path!
	err := rollbackQuarantine(origDir, qDir, &buf)
	if err != nil {
		t.Errorf("Expected rollbackQuarantine to succeed by restoring to collision-safe path; got err %v", err)
	}

	// Verify origDir still has its original file1.txt
	if _, err := os.Stat(filepath.Join(origDir, "file1.txt")); err != nil {
		t.Errorf("Original occupied directory data was improperly overwritten: %v", err)
	}

	// Verify qDir was moved to collision-safe restored path with file2.txt intact
	entries, _ := os.ReadDir(tmpDir)
	foundRestored := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "orig_occupied.restored-") {
			foundRestored = true
			restoredFilePath := filepath.Join(tmpDir, e.Name(), "file2.txt")
			if _, err := os.Stat(restoredFilePath); err != nil {
				t.Errorf("Restored collision-safe directory missing file2.txt: %v", err)
			}
		}
	}
	if !foundRestored {
		t.Errorf("Expected collision-safe restored path in %s", tmpDir)
	}

	if !strings.Contains(buf.String(), "[ROLLBACK COLLISION]") {
		t.Errorf("Expected [ROLLBACK COLLISION] message in log; got:\n%s", buf.String())
	}

	// Test non-existent quarantine path returns nil error
	if errNon := rollbackQuarantine(origDir, filepath.Join(tmpDir, "nonexistent")); errNon != nil {
		t.Errorf("Expected rollbackQuarantine on nonexistent path to return nil; got %v", errNon)
	}
}

func TestRevalidationUnreadableSubtree(t *testing.T) {
	tmpDir := t.TempDir()
	candDir := filepath.Join(tmpDir, "cand_dir_unreadable")
	os.MkdirAll(candDir, 0755)

	lockedSub := filepath.Join(candDir, "locked")
	os.MkdirAll(lockedSub, 0755)
	os.WriteFile(filepath.Join(lockedSub, "file.txt"), []byte("data"), 0644)

	info, _ := os.Lstat(candDir)
	sz, maxModTime, fCount, _ := getDirStats(candDir, time.Now())

	c := Candidate{
		ID:             5,
		Path:           candDir,
		Size:           sz,
		FileCount:      fCount,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		RootModTime:    info.ModTime(),
		ModTime:        maxModTime,
	}

	// Make sub-folder unreadable so revalidation fails
	os.Chmod(lockedSub, 0000)
	defer os.Chmod(lockedSub, 0755)

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if res.Aborted != 1 || res.Completed != 0 {
		t.Errorf("Expected 1 aborted action when subtree becomes unreadable; got aborted=%d, completed=%d", res.Aborted, res.Completed)
	}
	if !strings.Contains(stdout.String(), "[ABORT] Revalidation traversal failed") && !strings.Contains(stdout.String(), "[PROTECTED SAFEGUARD]") {
		t.Errorf("Expected ABORT Revalidation traversal failed or PROTECTED SAFEGUARD message; got:\n%s", stdout.String())
	}
	if _, err := os.Stat(candDir); os.IsNotExist(err) {
		t.Errorf("Candidate directory %s was deleted instead of rolled back!", candDir)
	}
}

func TestQuarantineIsolationFailureAbortsAction(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "missing_dir", "cand")

	c := Candidate{
		ID:             6,
		Path:           nonExistentPath,
		Size:           10,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	if res.Skipped != 1 {
		t.Errorf("Expected 1 skipped action for nonexistent path; got skipped=%d", res.Skipped)
	}
}

func TestExecutionFailureReturnsNonZeroExitCode(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Mock fzf binary so runMain reaches confirmAndDeleteWithIO
	fzfBin := filepath.Join(tmpHome, "fzf")
	os.WriteFile(fzfBin, []byte("#!/bin/sh\ncat\n"), 0755)
	t.Setenv("PATH", tmpHome+":"+os.Getenv("PATH"))

	tmpDir := t.TempDir()
	// Directory matching rule 'zig_cache' (.zig-cache) -> RiskClass = RiskRegenerable
	roDir := filepath.Join(tmpDir, ".zig-cache")
	os.MkdirAll(roDir, 0755)

	roFile := filepath.Join(roDir, "cache.bin")
	os.WriteFile(roFile, []byte(strings.Repeat("A", 120*1024)), 0644)

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(roDir, oldTime, oldTime)
	os.Chtimes(roFile, oldTime, oldTime)

	// Make directory read-only so deletion/trash fails
	os.Chmod(roDir, 0555)
	defer func() {
		_ = filepath.WalkDir(tmpDir, func(p string, d os.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(p, 0755)
			}
			return nil
		})
	}()

	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("y\n")

	// Execute runMain with -apply
	code := runMain([]string{"-apply", "-force-permanent", "-min-size-mb", "0.05", "-path", roDir}, &stdout, &stderr, stdin)

	if code != 1 {
		t.Errorf("Expected exit code 1 when deletion fails; got %d\nStdout:\n%s\nStderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestFzfSelectionAbove10kCandidates(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create 12,000 candidates
	candidates := make([]Candidate, 12000)
	for i := 0; i < 12000; i++ {
		candidates[i] = Candidate{
			ID:        i + 1,
			Path:      fmt.Sprintf("/tmp/candidate_%d.bin", i+1),
			Size:      1024,
			RiskClass: RiskRegenerable,
		}
	}

	// Mock FZF script that receives candidate inputs on stdin and outputs selected lines [1000], [10000], and [10001]
	fzfBinDir := filepath.Join(tmpHome, "bin")
	os.MkdirAll(fzfBinDir, 0755)
	fzfScript := filepath.Join(fzfBinDir, "fzf")
	if runtime.GOOS == "windows" {
		fzfScript += ".bat"
		os.WriteFile(fzfScript, []byte("@echo off\nfindstr /C:\"cand-1000\t\" /C:\"cand-10000\t\" /C:\"cand-10001\t\"\n"), 0755)
	} else {
		script := "#!/bin/sh\nawk -v RS='\\0' -v ORS='\\0' '/cand-1000\\t/ || /cand-10000\\t/ || /cand-10001\\t/'\n"
		os.WriteFile(fzfScript, []byte(script), 0755)
	}

	selected := runFzfInteractive(candidates, fzfScript, 100000, 50000, 50000)

	if len(selected) != 3 {
		t.Fatalf("Expected 3 selected candidates ([1000], [10000], [10001]); got %d", len(selected))
	}

	// Verify exact ID mappings
	idMap := make(map[int]string)
	for _, c := range selected {
		idMap[c.ID] = c.Path
	}

	if idMap[1000] != "/tmp/candidate_1000.bin" {
		t.Errorf("Expected candidate 1000 path /tmp/candidate_1000.bin; got %s", idMap[1000])
	}
	if idMap[10000] != "/tmp/candidate_10000.bin" {
		t.Errorf("CRITICAL BUG: Candidate 10000 was misparsed or mapped to wrong item! Got %s", idMap[10000])
	}
	if idMap[10001] != "/tmp/candidate_10001.bin" {
		t.Errorf("CRITICAL BUG: Candidate 10001 was misparsed or mapped to wrong item! Got %s", idMap[10001])
	}
}

func TestOrphanedQuarantineRecoveryAndScannerExclusion(t *testing.T) {
	tmpDir := t.TempDir()
	journalFile := filepath.Join(tmpDir, "journal.json")
	t.Setenv("UNSLOP_JOURNAL_PATH", journalFile)

	// 1. Create an orphaned quarantine directory whose original path is missing (journal owned)
	targetDir := filepath.Join(tmpDir, "target_cache")
	orphanedDir := targetDir + ".unslop-quarantine-12-1689000000"
	os.MkdirAll(orphanedDir, 0755)
	os.WriteFile(filepath.Join(orphanedDir, "saved_data.txt"), []byte("quarantine_data"), 0644)
	_ = recordQuarantineEntry(journalFile, QuarantineJournalEntry{
		OpID:           "op-12",
		OriginalPath:   targetDir,
		QuarantinePath: orphanedDir,
		Phase:          "quarantined",
		Timestamp:      time.Now(),
	})

	// 2. Create an orphaned quarantine file whose original path ALREADY EXISTS (journal owned)
	targetFile := filepath.Join(tmpDir, "stale.log")
	os.WriteFile(targetFile, []byte("new_stale_log"), 0644)
	orphanedFile := targetFile + ".unslop-quarantine-13-1689000000"
	os.WriteFile(orphanedFile, []byte("old_quarantined_log"), 0644)
	_ = recordQuarantineEntry(journalFile, QuarantineJournalEntry{
		OpID:           "op-13",
		OriginalPath:   targetFile,
		QuarantinePath: orphanedFile,
		Phase:          "quarantined",
		Timestamp:      time.Now(),
	})

	// 3. Create an UN-JOURNALED file matching quarantine name pattern
	unownedFile := filepath.Join(tmpDir, "unowned.log.unslop-quarantine-999")
	os.WriteFile(unownedFile, []byte("unowned_data"), 0644)

	// Verify ordinary plan-mode scan does NOT mutate any paths or recover quarantines automatically
	var stdoutScan, stderrScan bytes.Buffer
	scanCode := runMain([]string{"-path", tmpDir}, &stdoutScan, &stderrScan, strings.NewReader(""))
	if scanCode != 0 {
		t.Errorf("Expected runMain plan-mode scan exit code 0; got %d", scanCode)
	}
	if _, err := os.Lstat(orphanedDir); os.IsNotExist(err) {
		t.Errorf("Ordinary read-only scan mutated/restored quarantined directory %s", orphanedDir)
	}

	// Now run explicit quarantine recovery
	var buf bytes.Buffer
	cnt := recoverOrphanedQuarantines([]string{tmpDir}, &buf)

	if cnt != 2 {
		t.Fatalf("Expected 2 recovered quarantine items; got %d. Log:\n%s", cnt, buf.String())
	}

	// Verify targetDir was restored
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		t.Errorf("Target directory %s was not restored from orphaned quarantine", targetDir)
	}

	// Verify orphanedFile was restored to collision-safe path targetFile.restored-*
	entries, _ := os.ReadDir(tmpDir)
	foundRestored := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "stale.log.restored-") {
			foundRestored = true
			break
		}
	}
	if !foundRestored {
		t.Errorf("Expected restored collision-safe file stale.log.restored-* in %s", tmpDir)
	}

	// Verify un-journaled file was NOT touched/recovered
	if _, err := os.Stat(unownedFile); os.IsNotExist(err) {
		t.Errorf("Un-journaled file %s was improperly mutated/recovered", unownedFile)
	}

	// Test CLI -recover-quarantine flag via runMain
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"-recover-quarantine", "-path", tmpDir}, &stdout, &stderr, strings.NewReader(""))
	if code != 0 {
		t.Errorf("Expected runMain -recover-quarantine exit code 0; got %d", code)
	}
	if !strings.Contains(stdout.String(), "Quarantine recovery completed") {
		t.Errorf("Expected Quarantine recovery completed message; got:\n%s", stdout.String())
	}
}

func TestTransactionJournalOperations(t *testing.T) {
	tmpDir := t.TempDir()
	journalFile := filepath.Join(tmpDir, "journal.json")

	entry1 := QuarantineJournalEntry{
		OpID:           "op-1",
		OriginalPath:   "/tmp/orig1",
		QuarantinePath: "/tmp/orig1.unslop-quarantine-1",
		Phase:          "quarantined",
		Timestamp:      time.Now(),
	}

	if err := recordQuarantineEntry(journalFile, entry1); err != nil {
		t.Fatalf("Failed to record entry: %v", err)
	}

	entries, err := loadJournal(journalFile)
	if err != nil || len(entries) != 1 {
		t.Fatalf("Expected 1 journal entry; got %d, err: %v", len(entries), err)
	}
	if entries[0].OpID != "op-1" || entries[0].Phase != "quarantined" {
		t.Errorf("Unexpected entry data: %+v", entries[0])
	}

	// Update phase
	if err := updateJournalEntryPhase(journalFile, "op-1", "deleting"); err != nil {
		t.Fatalf("Failed to update phase: %v", err)
	}
	entries, _ = loadJournal(journalFile)
	if entries[0].Phase != "deleting" {
		t.Errorf("Expected phase 'deleting'; got '%s'", entries[0].Phase)
	}

	// Remove entry
	if err := removeJournalEntry(journalFile, "op-1"); err != nil {
		t.Fatalf("Failed to remove entry: %v", err)
	}
	entries, _ = loadJournal(journalFile)
	if len(entries) != 0 {
		t.Errorf("Expected 0 journal entries after removal; got %d", len(entries))
	}
}

func TestTrashAccountingAndFreeDesktopMetadataRecord(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// 1. Create a candidate file for trash execution
	trashFile := filepath.Join(tmpHome, "file_to_trash.txt")
	os.WriteFile(trashFile, []byte("data_to_trash"), 0644)
	info, _ := os.Lstat(trashFile)

	c := Candidate{
		ID:             1,
		Path:           trashFile,
		Size:           13,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
		RootModTime:    info.ModTime(),
		ModTime:        info.ModTime(),
	}

	var stdout bytes.Buffer
	// Execute deletion in default TRASH mode (useTrash = true)
	res := confirmAndDeleteWithIO([]Candidate{c}, false, false, true, 10000, 5000, &stdout, strings.NewReader("y\n"))

	if res.MovedToTrash != 13 {
		t.Errorf("Expected MovedToTrash == 13; got %d", res.MovedToTrash)
	}
	if res.FreedPermanently != 0 || res.Freed != 0 {
		t.Errorf("Expected FreedPermanently == 0 and Freed == 0 when moving to Trash; got FreedPermanently=%d, Freed=%d", res.FreedPermanently, res.Freed)
	}
	if !strings.Contains(stdout.String(), "Move to Trash (13 B staged; use -force-permanent to reclaim space)") {
		t.Errorf("Expected Trash DISK SAVINGS header in output; got:\n%s", stdout.String())
	}

	// 2. Check FreeDesktop .trashinfo record creation if Linux
	if runtime.GOOS == "linux" {
		trashInfoDir := filepath.Join(tmpHome, ".local", "share", "Trash", "info")
		entries, err := os.ReadDir(trashInfoDir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("Expected FreeDesktop Trash info file in %s; got err=%v", trashInfoDir, err)
		}
		if strings.Contains(entries[0].Name(), ".unslop-quarantine-") {
			t.Errorf("Trash info filename %s contains quarantine pattern", entries[0].Name())
		}
		infoData, _ := os.ReadFile(filepath.Join(trashInfoDir, entries[0].Name()))
		infoStr := string(infoData)
		if !strings.Contains(infoStr, "[Trash Info]") || !strings.Contains(infoStr, "Path=") {
			t.Errorf("Invalid FreeDesktop .trashinfo content:\n%s", infoStr)
		}
		if strings.Contains(infoStr, ".unslop-quarantine-") {
			t.Errorf("FreeDesktop .trashinfo Path contains quarantine pattern:\n%s", infoStr)
		}
	}

	// 3. Create a candidate file for permanent deletion
	permFile := filepath.Join(tmpHome, "file_to_perm.txt")
	os.WriteFile(permFile, []byte("data_perm"), 0644)
	infoP, _ := os.Lstat(permFile)

	cP := Candidate{
		ID:             2,
		Path:           permFile,
		Size:           9,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
		RootModTime:    infoP.ModTime(),
		ModTime:        infoP.ModTime(),
	}

	stdout.Reset()
	// Execute deletion in PERMANENT mode (useTrash = false)
	resP := confirmAndDeleteWithIO([]Candidate{cP}, false, false, false, 10000, 5000, &stdout, strings.NewReader("y\n"))

	if resP.FreedPermanently != 9 || resP.Freed != 9 {
		t.Errorf("Expected FreedPermanently == 9 and Freed == 9 in permanent mode; got FreedPermanently=%d, Freed=%d", resP.FreedPermanently, resP.Freed)
	}
	if resP.MovedToTrash != 0 {
		t.Errorf("Expected MovedToTrash == 0 in permanent mode; got %d", resP.MovedToTrash)
	}
}

func TestTransactionalTrashFallback(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// 1. Multiple same-second collision resolution
	file1 := filepath.Join(tmpHome, "same_name.txt")
	file2 := filepath.Join(tmpHome, "same_name_dup.txt")
	os.WriteFile(file1, []byte("content1"), 0644)
	os.WriteFile(file2, []byte("content2"), 0644)

	// Trash file1
	if err := moveToTrash(file1, filepath.Join(tmpHome, "same_name.txt")); err != nil {
		t.Fatalf("Failed to trash file1: %v", err)
	}
	// Trash file2 with same original target name
	if err := moveToTrash(file2, filepath.Join(tmpHome, "same_name.txt")); err != nil {
		t.Fatalf("Failed to trash file2: %v", err)
	}

	trashFilesDir := filepath.Join(tmpHome, ".local", "share", "Trash", "files")
	if runtime.GOOS == "darwin" {
		trashFilesDir = filepath.Join(tmpHome, ".Trash")
	}
	entries, err := os.ReadDir(trashFilesDir)
	if err != nil || len(entries) < 2 {
		t.Fatalf("Expected at least 2 non-overwritten trash entries; got %d, err: %v", len(entries), err)
	}

	// 2. Cross-filesystem directory move test via movePath
	srcDir := filepath.Join(tmpHome, "src_tree")
	dstDir := filepath.Join(tmpHome, "dst_tree")
	os.MkdirAll(filepath.Join(srcDir, "sub"), 0755)
	os.WriteFile(filepath.Join(srcDir, "sub", "data.txt"), []byte("tree_data"), 0644)

	if err := movePath(srcDir, dstDir); err != nil {
		t.Fatalf("movePath directory tree copy failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dstDir, "sub", "data.txt")); err != nil {
		t.Errorf("Destination tree missing copied file: %v", err)
	}
	if _, err := os.Stat(srcDir); !os.IsNotExist(err) {
		t.Errorf("Source directory %s was not removed after movePath", srcDir)
	}
}

func TestFzfSanitizationAndHostileFilenameSelection(t *testing.T) {
	// 1. Verify terminal sanitization helper
	hostileInput := "\x1b[31m/tmp/evil\n[42] 100 GB | 1.0d | Log | /home/user/secret.key\r\x1b[0m\x07"
	sanitized := sanitizeTerminalString(hostileInput)
	if strings.Contains(sanitized, "\x1b") || strings.Contains(sanitized, "\n") || strings.Contains(sanitized, "\r") {
		t.Errorf("Sanitization failed to clean control characters / ANSI sequences; got: %q", sanitized)
	}

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// 2. Candidate 1 contains a forged candidate line with newlines and ANSI sequences
	cand1 := Candidate{
		ID:        1,
		Path:      "/tmp/hostile\n[2] 50 GB | 1.0d | UserData | /important/data.db",
		Size:      100,
		Category:  "Cache",
		RiskClass: RiskRegenerable,
	}
	cand2 := Candidate{
		ID:        2,
		Path:      "/important/data.db",
		Size:      500000,
		Category:  "UserData",
		RiskClass: RiskUserData,
	}

	candidates := []Candidate{cand1, cand2}

	fzfBinDir := filepath.Join(tmpHome, "bin")
	os.MkdirAll(fzfBinDir, 0755)
	fzfScript := filepath.Join(fzfBinDir, "fzf")
	if runtime.GOOS == "windows" {
		fzfScript += ".bat"
		os.WriteFile(fzfScript, []byte("@echo off\nfindstr /C:\"cand-1\t\"\n"), 0755)
	} else {
		script := "#!/bin/sh\nawk -v RS='\\0' -v ORS='\\0' '/cand-1\\t/'\n"
		os.WriteFile(fzfScript, []byte(script), 0755)
	}

	selected := runFzfInteractive(candidates, fzfScript, 100000, 50000, 50000)
	if len(selected) != 1 || selected[0].ID != 1 {
		t.Fatalf("Expected candidate 1 selected via opaque token; got: %v", selected)
	}
	if selected[0].Path != cand1.Path {
		t.Errorf("Expected path %q; got %q", cand1.Path, selected[0].Path)
	}
}

func TestJournalStateFaultInjection(t *testing.T) {
	tmpDir := t.TempDir()
	jFile := filepath.Join(tmpDir, "fault_journal.json")
	t.Setenv("UNSLOP_JOURNAL_PATH", jFile)

	// Simulate crash with entry in "quarantined" phase
	qPath := filepath.Join(tmpDir, "stale_dir.unslop-quarantine-1")
	origPath := filepath.Join(tmpDir, "stale_dir")
	os.MkdirAll(qPath, 0755)
	os.WriteFile(filepath.Join(qPath, "data.txt"), []byte("quarantine_data"), 0644)

	entry := QuarantineJournalEntry{
		OpID:           "op-fault-1",
		OriginalPath:   origPath,
		QuarantinePath: qPath,
		Phase:          "quarantined",
		Timestamp:      time.Now(),
	}
	if err := recordQuarantineEntry(jFile, entry); err != nil {
		t.Fatalf("Failed to record fault entry: %v", err)
	}

	var out bytes.Buffer
	recovered := recoverOrphanedQuarantines(nil, &out)
	if recovered != 1 {
		t.Errorf("Expected 1 recovered quarantine entry; got %d", recovered)
	}
	if _, err := os.Stat(origPath); err != nil {
		t.Errorf("Expected origPath to be restored; got err: %v", err)
	}

	// Verify journal entry cleaned up after recovery
	entries, _ := loadJournal(jFile)
	if len(entries) != 0 {
		t.Errorf("Expected journal to be empty after recovery; got %d entries", len(entries))
	}
}

func TestMountAndReparsePointRefusal(t *testing.T) {
	tmpDir := t.TempDir()
	candDir := filepath.Join(tmpDir, "mount_cand")
	os.MkdirAll(candDir, 0755)
	targetFile := filepath.Join(tmpDir, "target_outside.txt")
	os.WriteFile(targetFile, []byte("outside"), 0644)

	// Create symlink inside candidate directory pointing outside
	symlinkPath := filepath.Join(candDir, "link_outside")
	os.Symlink(targetFile, symlinkPath)

	hasBoundary, bPath, err := containsMountOrReparsePoint(candDir)
	if !hasBoundary {
		t.Fatalf("Expected containsMountOrReparsePoint to return true for symlink boundary")
	}
	if bPath != symlinkPath {
		t.Errorf("Expected boundary path %s; got %s", symlinkPath, bPath)
	}
	if err == nil {
		t.Errorf("Expected non-nil boundary error")
	}

	// Verify confirmAndDeleteWithIO refuses permanent deletion when boundary present
	info, _ := os.Lstat(candDir)
	qSize, qMaxModTime, qFileCount, _, _ := inspectDirectorySubtree(candDir, time.Now())
	cand := Candidate{
		ID:             1,
		Path:           candDir,
		Size:           qSize,
		FileCount:      qFileCount,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		ModTime:        qMaxModTime,
		RootModTime:    info.ModTime(),
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 500, &stdout, strings.NewReader("y\n"))
	if res.Aborted != 1 {
		t.Errorf("Expected permanent deletion to be aborted for mount/reparse-point boundary; got Aborted=%d", res.Aborted)
	}
	if !strings.Contains(stdout.String(), "[REFUSED]") {
		t.Errorf("Expected [REFUSED] in output log; got:\n%s", stdout.String())
	}
}

func TestPythonVenvRuleRequiresPyvenvCfg(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Directory named .env in a Python project must NOT be matched as python_venv
	envSecretDir := filepath.Join(tmpDir, ".env")
	os.MkdirAll(envSecretDir, 0755)
	os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte("[tool.poetry]"), 0644)

	manifest, _ := loadManifest("manifest.json")
	engine := NewRuleEngine(manifest)

	rule1, _, _ := engine.MatchDir(".env", envSecretDir, nil)
	if rule1 != nil && rule1.ID == "python_venv" {
		t.Errorf("Directory .env should not be matched as python_venv!")
	}

	// 2. Directory named venv WITHOUT pyvenv.cfg must NOT be matched as python_venv
	venvNoCfgDir := filepath.Join(tmpDir, "venv")
	os.MkdirAll(venvNoCfgDir, 0755)
	rule2, _, _ := engine.MatchDir("venv", venvNoCfgDir, nil)
	if rule2 != nil && rule2.ID == "python_venv" {
		t.Errorf("Directory venv without pyvenv.cfg should not be matched as python_venv!")
	}

	// 3. Directory named venv WITH pyvenv.cfg MUST be matched as python_venv
	os.WriteFile(filepath.Join(venvNoCfgDir, "pyvenv.cfg"), []byte("home = /usr/bin"), 0644)
	rule3, _, _ := engine.MatchDir("venv", venvNoCfgDir, nil)
	if rule3 == nil || rule3.ID != "python_venv" {
		t.Errorf("Directory venv with pyvenv.cfg must be matched as python_venv!")
	}
}

func TestPackageRegistryExclusionAndRecentAtimeSafety(t *testing.T) {
	if !isPackageRegistryInternalPath("/home/user/.cargo/registry/src/index.crates.io-123/gdextension-api-0.1.0/api.json") {
		t.Errorf("Expected isPackageRegistryInternalPath to return true for Cargo registry file")
	}

	tmpDir := t.TempDir()
	cargoFile := filepath.Join(tmpDir, ".cargo", "registry", "src", "gdextension.json")
	os.MkdirAll(filepath.Dir(cargoFile), 0755)
	os.WriteFile(cargoFile, []byte(strings.Repeat("B", 6*1024*1024)), 0644)

	// Verify scanParallel ignores single files inside .cargo/registry
	manifest, _ := loadManifest("manifest.json")
	engine := NewRuleEngine(manifest)

	cands := scanParallel([]string{tmpDir}, engine, 7.0, 0, true)
	for _, c := range cands {
		if strings.Contains(c.Path, ".cargo/registry") {
			t.Errorf("Single file inside package registry should not be scanned as candidate: %s", c.Path)
		}
	}
}
