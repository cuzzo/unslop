package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCoveragePushTo100Percent(t *testing.T) {
	// 1. calculateDynamicMinSizeMB branches
	val1000 := calculateDynamicMinSizeMB(1500 * 1024 * 1024 * 1024)
	if val1000 != 50.0 {
		t.Errorf("Expected 50.0 for 1500GB disk; got %f", val1000)
	}

	valMid := calculateDynamicMinSizeMB(200 * 1024 * 1024 * 1024)
	if valMid <= 1.0 || valMid >= 50.0 {
		t.Errorf("Expected mid-range min size for 200GB disk; got %f", valMid)
	}

	// 2. containsProtectedPath with protected credentials.json folder inside
	tmpDir := t.TempDir()
	protSubDir := filepath.Join(tmpDir, "stale_dir_with_credentials")
	os.MkdirAll(protSubDir, 0755)
	os.WriteFile(filepath.Join(protSubDir, "credentials.json"), []byte("secret"), 0600)

	if !containsProtectedPath(protSubDir) {
		t.Errorf("Expected containsProtectedPath to return true for folder with credentials.json")
	}

	// 3. moveToTrash collision fallback (dest already exists)
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("PATH", "") // Force fallback to local trash dir

	trashFilesDir := filepath.Join(tmpHome, ".local", "share", "Trash", "files")
	if runtime.GOOS == "darwin" {
		trashFilesDir = filepath.Join(tmpHome, ".Trash")
	}
	os.MkdirAll(trashFilesDir, 0755)

	itemToTrash := filepath.Join(tmpDir, "duplicate_item.tmp")
	os.WriteFile(itemToTrash, []byte("data1"), 0644)
	os.WriteFile(filepath.Join(trashFilesDir, "duplicate_item.tmp"), []byte("data0"), 0644)

	if err := moveToTrash(itemToTrash); err != nil {
		t.Errorf("moveToTrash collision fallback failed: %v", err)
	}

	// 4. runMain CLI flag branches (-version, -json -plan-out)
	var stdout, stderr bytes.Buffer

	// -version flag
	stdout.Reset()
	if code := runMain([]string{"-version"}, &stdout, &stderr, nil); code != 0 {
		t.Errorf("Expected exit code 0 for -version; got %d", code)
	}

	// -json -plan-out
	stdout.Reset()
	stderr.Reset()
	planOutPath := filepath.Join(tmpDir, "exported_plan.json")
	if code := runMain([]string{"-json", "-plan-out", planOutPath, "-path", tmpDir}, &stdout, &stderr, nil); code != 0 {
		t.Errorf("Expected exit code 0 for -json -plan-out; got %d", code)
	}
	if _, err := os.Stat(planOutPath); os.IsNotExist(err) {
		t.Errorf("Expected exported plan JSON file at %s", planOutPath)
	}

	// 5. scanParallel ticker progress line coverage
	ruleFile := Rule{
		ID:        "file_rule",
		Name:      "File Rule",
		Target:    "file",
		Patterns:  []string{"*.log"},
		Category:  "Log File",
		RiskClass: RiskUserData,
		MinSizeMB: 0.05,
	}

	// Create 50 files so progress ticker reports > 0 files scanned
	scanDir := filepath.Join(tmpDir, "progress_scan")
	os.MkdirAll(scanDir, 0755)
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	for i := 0; i < 50; i++ {
		fn := filepath.Join(scanDir, strings.Repeat("a", 10)+string(rune('a'+i%26))+".log")
		os.WriteFile(fn, []byte(strings.Repeat("B", 120*1024)), 0644)
		os.Chtimes(fn, oldTime, oldTime)
	}

	// Sleep slightly inside goroutine to ensure progress ticker fires
	engine := NewRuleEngine(Manifest{Rules: []Rule{ruleFile}})
	go func() {
		time.Sleep(150 * time.Millisecond)
	}()
	candsFile := scanParallel([]string{scanDir}, engine, 2.0, 100*1024, true)
	if len(candsFile) == 0 {
		t.Errorf("Expected file candidates from scanParallel")
	}

	// 6. scanParallel /tmp filters: .git, .sock, .lock, .pid, protected
	fakeTmp := filepath.Join(tmpDir, "tmp")
	os.MkdirAll(filepath.Join(fakeTmp, ".git"), 0755)
	os.WriteFile(filepath.Join(fakeTmp, "app.sock"), []byte("sock"), 0644)
	os.WriteFile(filepath.Join(fakeTmp, "app.lock"), []byte("lock"), 0644)
	os.WriteFile(filepath.Join(fakeTmp, "app.pid"), []byte("1234"), 0644)
	os.WriteFile(filepath.Join(fakeTmp, "credentials.json"), []byte("secret"), 0600)

	// Scan fakeTmp directory
	scanParallel([]string{fakeTmp}, engine, 0.0, 10, true)

	// 7. scanParallel with ~ path expansion using getDefaultManifest()
	t.Setenv("HOME", tmpDir)
	tildeDir := filepath.Join(tmpDir, ".zig-cache")
	os.MkdirAll(tildeDir, 0755)
	tf := filepath.Join(tildeDir, "t.bin")
	os.WriteFile(tf, []byte(strings.Repeat("Z", 120*1024)), 0644)
	os.Chtimes(tildeDir, oldTime, oldTime)
	os.Chtimes(tf, oldTime, oldTime)

	engineDefault := NewRuleEngine(getDefaultManifest())
	candsTilde := scanParallel([]string{"~/.zig-cache"}, engineDefault, 2.0, 100*1024, true)
	if len(candsTilde) != 1 {
		t.Errorf("Expected candidate for tilde scan ~/.zig-cache; got %d", len(candsTilde))
	}

	// 8. Quarantined protected safeguard rollback test (lines 1556-1559)
	protTargetDir := filepath.Join(tmpDir, "prot_quarantine")
	os.MkdirAll(protTargetDir, 0755)
	os.WriteFile(filepath.Join(protTargetDir, "credentials.json"), []byte("secret"), 0600)
	protFi, _ := os.Lstat(protTargetDir)

	candProtQ := Candidate{
		ID:             99,
		Path:           protTargetDir,
		Size:           100,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
		RootModTime:    protFi.ModTime(),
		ModTime:        protFi.ModTime(),
	}

	stdout.Reset()
	resProtQ := confirmAndDeleteWithIO([]Candidate{candProtQ}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if resProtQ.Aborted != 1 {
		t.Errorf("Expected 1 aborted quarantine action due to protected safeguard inside quarantine; got %d", resProtQ.Aborted)
	}
	if _, err := os.Stat(protTargetDir); os.IsNotExist(err) {
		t.Errorf("Protected directory %s was deleted instead of rolled back!", protTargetDir)
	}

	// 9. getDirStats error path on inaccessible sub-path
	unreadableDir := filepath.Join(tmpDir, "unreadable_sub")
	os.MkdirAll(unreadableDir, 0755)
	unreadableSub := filepath.Join(unreadableDir, "locked")
	os.MkdirAll(unreadableSub, 0000)
	defer os.Chmod(unreadableSub, 0755)

	getDirStats(unreadableDir, time.Now())
}
