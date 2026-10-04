package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/platform"
	"github.com/yahn/unslop/internal/scanner"
)

func TestConfirmationRevalidatesChangedSize(t *testing.T) {
	for _, isDir := range []bool{false, true} {
		root := t.TempDir()
		path := filepath.Join(root, "cache")
		file := path
		if isDir {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			file = filepath.Join(path, "payload")
		}
		if err := os.WriteFile(file, []byte("before"), 0600); err != nil {
			t.Fatal(err)
		}
		target := "file"
		if isDir {
			target = "dir"
		}
		manifest := config.Manifest{Rules: []config.Rule{{ID: "cache", Target: target, Patterns: []string{"cache"}, RiskClass: config.RiskRegenerable}}}
		items, err := scanner.ScanParallelChecked([]string{path}, config.NewRuleEngine(manifest), 0, 0, 0, false)
		if err != nil || len(items) != 1 {
			t.Fatalf("scan=%+v err=%v", items, err)
		}
		if err := os.WriteFile(file, []byte("changed size"), 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		result := ConfirmAndDeleteWithIO(items, false, false, false, strings.NewReader("y\n"), &out, &out, 0, manifest)
		if result.DeletedCount != 0 || result.Skipped != 1 || !strings.Contains(out.String(), "size changed") {
			t.Fatalf("result=%+v output=%s", result, out.String())
		}
		if _, err := os.Stat(file); err != nil {
			t.Fatal("changed file was removed", err)
		}
	}
}

func TestPermanentDeleteFailureRollsBackNativeDirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	parent := t.TempDir()
	path := filepath.Join(parent, "cache")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "payload"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0700)
	t.Setenv("UNSLOP_JOURNAL_PATH", filepath.Join(t.TempDir(), "journal.json"))
	manifest := config.Manifest{Rules: []config.Rule{{ID: "cache", Target: "dir", Patterns: []string{"cache"}, RiskClass: config.RiskRegenerable}}}
	items, err := scanner.ScanParallelChecked([]string{path}, config.NewRuleEngine(manifest), 0, 0, 0, false)
	if err != nil || len(items) != 1 {
		t.Fatalf("scan=%+v err=%v", items, err)
	}
	var out bytes.Buffer
	result := ConfirmAndDeleteWithIO(items, false, false, false, strings.NewReader("y\n"), &out, &out, 0, manifest)
	if result.DeletedCount != 0 || result.Skipped != 1 || len(result.Errors) != 1 || !strings.Contains(out.String(), "DELETE FAILURE") {
		t.Fatalf("result=%+v output=%s", result, out.String())
	}
	data, err := os.ReadFile(filepath.Join(path, "payload"))
	if err != nil || string(data) != "preserve" {
		t.Fatalf("rollback payload=%q err=%v", data, err)
	}
	entries, err := loadJournal(getJournalPath())
	if err != nil || len(entries) != 0 {
		t.Fatalf("journal=%+v err=%v", entries, err)
	}
}

func TestMacConfirmationTrashCommitAndRollback(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getuid() == 0 {
		t.Skip("macOS trash adapter and POSIX permissions")
	}
	for _, operation := range []string{"commit", "rollback", "rollback-failure"} {
		t.Run(operation, func(t *testing.T) {
			home, parent, bin := t.TempDir(), t.TempDir(), t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("PATH", bin)
			t.Setenv("UNSLOP_JOURNAL_PATH", filepath.Join(home, "journal.json"))
			path := filepath.Join(parent, "payload")
			if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			item := scanner.Candidate{Path: path, Size: info.Size(), ModTime: info.ModTime(), RiskClass: config.RiskRegenerable, CanDelete: true}
			script := "exit 7"
			if operation == "commit" {
				script = `/bin/mkdir -p "$HOME/.Trash"; exec /bin/mv "$1" "$HOME/.Trash/"`
			}
			if operation == "rollback-failure" {
				script = `/bin/chmod 0500 "$(/usr/bin/dirname "$1")"; exit 7`
			}
			if err := os.WriteFile(filepath.Join(bin, "trash"), []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(parent, 0700)
			var out bytes.Buffer
			result := ConfirmAndDeleteWithIO([]scanner.Candidate{item}, false, true, false, strings.NewReader("y\n"), &out, &out, 0, config.Manifest{})
			entries, err := loadJournal(getJournalPath())
			if err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "commit":
				files, err := os.ReadDir(filepath.Join(home, ".Trash"))
				if err != nil || len(files) != 1 || result.DeletedCount != 1 || result.DeletedBytes != info.Size() || len(entries) != 0 {
					t.Fatalf("result=%+v trash=%+v journal=%+v err=%v", result, files, entries, err)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("committed source remains", err)
				}
			case "rollback":
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "preserve" || result.DeletedCount != 0 || result.Skipped != 1 || len(entries) != 0 {
					t.Fatalf("result=%+v data=%q journal=%+v err=%v", result, data, entries, err)
				}
			case "rollback-failure":
				if !strings.Contains(out.String(), "ROLLBACK CRITICAL") || len(entries) != 1 || result.DeletedCount != 0 {
					t.Fatalf("result=%+v journal=%+v output=%s", result, entries, out.String())
				}
				if err := os.Chmod(parent, 0700); err != nil {
					t.Fatal(err)
				}
				RecoverOrphanedQuarantines(nil, &out)
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "preserve" {
					t.Fatalf("recovery data=%q err=%v", data, err)
				}
			}
		})
	}
}

func TestMacTrashUsesNativeAdapter(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS adapter")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	p := filepath.Join(home, "fixture")
	if err := os.WriteFile(p, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := moveToTrash(p); err == nil {
		t.Fatal("must fail without native adapter instead of silently using Linux Trash")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("fixture must remain on failure", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local/share/Trash")); !os.IsNotExist(err) {
		t.Fatal("created Linux Trash on Mac")
	}
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "trash"), []byte("#!/bin/sh\n/bin/mkdir -p \"$HOME/.Trash\"\nexec /bin/mv \"$1\" \"$HOME/.Trash/\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if err := moveToTrash(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".Trash/fixture")); err != nil {
		t.Fatal("native adapter did not receive fixture", err)
	}
}

func TestUserDataRequiresApplyData(t *testing.T) {
	t.Setenv("UNSLOP_JOURNAL_PATH", filepath.Join(t.TempDir(), "journal.json"))
	p := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(p, []byte("history"), 0600); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	c := scanner.Candidate{Path: p, Size: fi.Size(), ModTime: fi.ModTime(), RiskClass: config.RiskUserData, CanDelete: true}
	var out bytes.Buffer
	ConfirmAndDeleteWithIO([]scanner.Candidate{c}, false, false, false, strings.NewReader("y\n"), &out, &out, 0, config.Manifest{})
	if _, err := os.Stat(p); err != nil {
		t.Fatal("user data removed without -apply-data", err)
	}
}

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
		Path:        sampleFile,
		Size:        14,
		AgeDays:     10.0,
		Category:    "Cache Dir",
		RiskClass:   config.RiskRegenerable,
		CanDelete:   true,
		ModTime:     info.ModTime(),
		RootModTime: info.ModTime(),
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

	res := ConfirmAndDeleteWithIO([]scanner.Candidate{cand}, false, false, false, strings.NewReader("y\n"), &stdout, &stderr, 1000, manifest)

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
		Path:        sampleFile,
		Size:        13,
		AgeDays:     10.0,
		Category:    "Cache Dir",
		RiskClass:   config.RiskRegenerable,
		CanDelete:   true,
		ModTime:     info.ModTime(),
		RootModTime: info.ModTime(),
		DeviceID:    dev,
		InodeNum:    ino,
		HasIdentity: hasId,
	}

	if !hasId {
		t.Skip("filesystem identity unavailable")
	}
	if err := os.Rename(sampleFile, filepath.Join(tmpDir, "original.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sampleFile, []byte("ORIGINAL DATA"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sampleFile, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
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

	res := ConfirmAndDeleteWithIO([]scanner.Candidate{cand}, false, false, false, strings.NewReader("y\n"), &stdout, &stderr, 1000, manifest)

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

func TestOrphanRecoveryRestoresDirectoryWithoutOverwritingAnExistingPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	root := t.TempDir()
	for _, name := range []string{"cache", "occupied"} {
		path := filepath.Join(root, name+".unslop-quarantine-fixture")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "payload"), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "occupied"), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if count := RecoverOrphanedQuarantines([]string{root}, &output); count != 1 {
		t.Fatalf("restored=%d output=%s", count, &output)
	}
	for _, path := range []string{"cache/payload", "occupied.unslop-quarantine-fixture/payload"} {
		if data, err := os.ReadFile(filepath.Join(root, path)); err != nil || string(data) != "keep" {
			t.Fatalf("recovery lost %s: %s %v", path, data, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "occupied")); err != nil || string(data) != "existing" {
		t.Fatalf("recovery overwrote existing path: %s %v", data, err)
	}
}

func TestConfirmationDoesNotQueryUnusedPackageManagers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command fixture")
	}
	root := t.TempDir()
	marker := filepath.Join(root, "queried")
	t.Setenv("UNSLOP_QUERY_MARKER", marker)
	for _, name := range []string{"cargo", "npm", "pipx", "dotnet", "composer", "zvm"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("#!/bin/sh\nprintf queried > \"$UNSLOP_QUERY_MARKER\"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", root)
	var output bytes.Buffer
	ConfirmAndDeleteWithIO([]scanner.Candidate{{Path: filepath.Join(root, "cache"), CanDelete: true}}, true, false, false, strings.NewReader(""), &output, &output, 0, config.Manifest{})
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("confirmation queried package managers whose inventory is never used")
	}
}
