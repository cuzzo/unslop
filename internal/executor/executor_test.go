package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/platform"
	"github.com/yahn/unslop/internal/scanner"
)

func TestDurableJournalAtomicTempWriteFsyncAndRename(t *testing.T) {
	tmpDir := t.TempDir()
	jPath := filepath.Join(tmpDir, "test-journal.json")

	entry := QuarantineJournalEntry{
		OpID:           "test-op-1",
		OriginalPath:   "/tmp/orig-1",
		QuarantinePath: "/tmp/quarantine-1",
		Phase:          "isolated",
		Timestamp:      time.Now(),
	}

	if err := recordQuarantineEntry(jPath, entry); err != nil {
		t.Fatalf("recordQuarantineEntry failed: %v", err)
	}

	entries, err := loadJournal(jPath)
	if err != nil {
		t.Fatalf("loadJournal failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Expected 1 journal entry; got %d", len(entries))
	}
	if entries[0].OpID != "test-op-1" {
		t.Errorf("Expected OpID 'test-op-1'; got '%s'", entries[0].OpID)
	}
}

func TestDurableJournalRefusesActionOnUnwritableJournal(t *testing.T) {
	tmpDir := t.TempDir()

	unwritableJournal := filepath.Join(tmpDir, "invalid-dir", "journal.json")

	sampleFile := filepath.Join(tmpDir, "precious_data.bin")
	os.WriteFile(sampleFile, []byte("IMPORTANT DATA"), 0644)
	info, _ := os.Lstat(sampleFile)

	cand := scanner.Candidate{
		ID:             1,
		Path:           sampleFile,
		Size:           14,
		AgeDays:        10.0,
		Category:       "Cache Dir",
		RuleID:         "test_rule",
		RiskClass:      config.RiskRegenerable,
		ProposedAction: "delete_file",
		CanDelete:      true,
		ModTime:        info.ModTime(),
		RootModTime:    info.ModTime(),
	}

	t.Setenv("UNSLOP_JOURNAL_PATH", unwritableJournal)
	os.Chmod(tmpDir, 0500)
	defer os.Chmod(tmpDir, 0700)

	var stdout, stderr bytes.Buffer
	manifest := config.Manifest{
		Rules: []config.Rule{
			{
				ID:        "test_rule",
				Target:    "file",
				Patterns:  []string{"precious_data.bin"},
				RiskClass: config.RiskRegenerable,
			},
		},
	}

	res := ConfirmAndDeleteWithIO([]scanner.Candidate{cand}, false, false, false, strings.NewReader("y\n"), &stdout, &stderr, 1000, 1000, 1000, manifest)

	if res.DeletedCount != 0 {
		t.Errorf("Expected 0 deleted items when journal is unwritable; got %d", res.DeletedCount)
	}

	if _, err := os.Stat(sampleFile); os.IsNotExist(err) {
		t.Errorf("FAIL-CLOSED VIOLATION: Sample file was deleted despite journal write failure!")
	}

	errStr := stderr.String()
	if !strings.Contains(errStr, "TRANSACTION FAILURE") && !strings.Contains(errStr, "Journal write failed") {
		t.Errorf("Expected TRANSACTION FAILURE error output; got:\n%s", errStr)
	}
}

func TestConcurrentProcessesJournalLocking(t *testing.T) {
	tmpDir := t.TempDir()
	jPath := filepath.Join(tmpDir, "concurrent-journal.json")

	const numGoroutines = 10
	const entriesPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(gID int) {
			defer wg.Done()
			for i := 0; i < entriesPerGoroutine; i++ {
				opID := fmt.Sprintf("g%d-e%d", gID, i)
				entry := QuarantineJournalEntry{
					OpID:           opID,
					OriginalPath:   fmt.Sprintf("/orig/%s", opID),
					QuarantinePath: fmt.Sprintf("/quarantine/%s", opID),
					Phase:          "isolated",
					Timestamp:      time.Now(),
				}
				if err := recordQuarantineEntry(jPath, entry); err != nil {
					t.Errorf("Concurrent recordQuarantineEntry failed for %s: %v", opID, err)
				}
			}
		}(g)
	}

	wg.Wait()

	entries, err := loadJournal(jPath)
	if err != nil {
		t.Fatalf("Failed to load journal after concurrent writes: %v", err)
	}

	expectedTotal := numGoroutines * entriesPerGoroutine
	if len(entries) != expectedTotal {
		t.Fatalf("Expected exactly %d total journal entries after concurrent writes; got %d", expectedTotal, len(entries))
	}
}

func TestMovePathUsesAtomicRenameWithoutCopyFallback(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src_file.txt")
	dst := filepath.Join(tmpDir, "dst_file.txt")

	os.WriteFile(src, []byte("DATA"), 0644)

	if err := movePath(src, dst); err != nil {
		t.Fatalf("movePath failed on same filesystem: %v", err)
	}

	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("Expected src to be moved; src still exists")
	}

	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "DATA" {
		t.Errorf("Expected dst content 'DATA'; got error %v, data '%s'", err, string(data))
	}
}

func TestMoveToTrashFailsSafelyWhenNoOSUtility(t *testing.T) {
	t.Setenv("PATH", "")
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_trash.tmp")
	os.WriteFile(tmpFile, []byte("DATA"), 0644)

	t.Setenv("HOME", "/nonexistent_home_dir_12345")

	err := moveToTrash(tmpFile)
	if err == nil {
		t.Errorf("Expected moveToTrash to return error when home trash and OS trash fail")
	}

	if _, errStat := os.Stat(tmpFile); os.IsNotExist(errStat) {
		t.Errorf("FAIL-SAFE VIOLATION: Source file was deleted despite trash failure!")
	}
}

func TestObjectIdentityReplacementRaceAbortsDeletion(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "race_target.bin")
	os.WriteFile(sampleFile, []byte("ORIGINAL DATA"), 0644)
	info, _ := os.Lstat(sampleFile)

	dev, ino, hasId := platform.GetFileIdentity(sampleFile, info)

	cand := scanner.Candidate{
		ID:             1,
		Path:           sampleFile,
		Size:           13,
		AgeDays:        10.0,
		Category:       "Cache Dir",
		RuleID:         "test_rule",
		RiskClass:      config.RiskRegenerable,
		ProposedAction: "delete_file",
		CanDelete:      true,
		ModTime:        info.ModTime(),
		RootModTime:    info.ModTime(),
		DeviceID:       dev + 999, // Injected fake device ID to simulate object identity mutation / replacement race
		InodeNum:       ino + 999, // Injected fake inode number
		HasIdentity:    hasId,
	}

	var stdout, stderr bytes.Buffer
	manifest := config.Manifest{
		Rules: []config.Rule{
			{
				ID:        "test_rule",
				Target:    "file",
				Patterns:  []string{"race_target.bin"},
				RiskClass: config.RiskRegenerable,
			},
		},
	}

	res := ConfirmAndDeleteWithIO([]scanner.Candidate{cand}, false, false, false, strings.NewReader("y\n"), &stdout, &stderr, 1000, 1000, 1000, manifest)

	if res.DeletedCount != 0 {
		t.Errorf("Expected 0 deleted items when object identity mutates; got %d", res.DeletedCount)
	}

	if _, err := os.Stat(sampleFile); os.IsNotExist(err) {
		t.Errorf("REPLACEMENT RACE FAILURE: File was deleted despite object identity mutation!")
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "object identity mutated") && !strings.Contains(outStr, "Replacement race detected") {
		t.Errorf("Expected object identity mutation warning; got output:\n%s", outStr)
	}
}
