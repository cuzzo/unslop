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
	if !strings.Contains(stdout.String(), "Action refused") && !strings.Contains(stdout.String(), "report-only") {
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

	// Attempt to rename qDir to origDir when origDir is an occupied directory -> os.Rename returns error!
	err := rollbackQuarantine(origDir, qDir)
	if err == nil {
		t.Errorf("Expected rollbackQuarantine to return error when origDir is occupied")
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
	defer os.Chmod(roDir, 0755)

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
		os.WriteFile(fzfScript, []byte("@echo off\nfindstr /C:\"[10000]\" /C:\"[10001]\" /C:\"[1000]\"\n"), 0755)
	} else {
		script := "#!/bin/sh\nawk '/\\[1000\\]/ || /\\[10000\\]/ || /\\[10001\\]/'\n"
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

	// 1. Create an orphaned quarantine directory whose original path is missing
	targetDir := filepath.Join(tmpDir, "target_cache")
	orphanedDir := targetDir + ".unslop-quarantine-12-1689000000"
	os.MkdirAll(orphanedDir, 0755)
	os.WriteFile(filepath.Join(orphanedDir, "saved_data.txt"), []byte("quarantine_data"), 0644)

	// 2. Create an orphaned quarantine file whose original path ALREADY EXISTS
	targetFile := filepath.Join(tmpDir, "stale.log")
	os.WriteFile(targetFile, []byte("new_stale_log"), 0644)
	orphanedFile := targetFile + ".unslop-quarantine-13-1689000000"
	os.WriteFile(orphanedFile, []byte("old_quarantined_log"), 0644)

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
		infoData, _ := os.ReadFile(filepath.Join(trashInfoDir, entries[0].Name()))
		if !strings.Contains(string(infoData), "[Trash Info]") || !strings.Contains(string(infoData), "Path=") {
			t.Errorf("Invalid FreeDesktop .trashinfo content:\n%s", string(infoData))
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
