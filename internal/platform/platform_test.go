package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
)

func TestPosixFilesystemHelpersReportMissingPathsAndUnavailableIdentity(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("POSIX filesystem helpers")
	}
	info, err := (fstest.MapFS{"portable": &fstest.MapFile{Data: []byte("portable")}}).Stat("portable")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, available := GetFileIdentity("portable", info); available {
		t.Fatal("invented identity for filesystem without native metadata")
	}
	if device, err := getDeviceIDFromInfo(info); err != nil || device != 0 {
		t.Fatalf("invented device for portable metadata: %d %v", device, err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if boundary, _, err := ContainsMountOrReparsePoint(missing); !boundary || err == nil {
		t.Fatalf("missing root accepted: boundary=%t err=%v", boundary, err)
	}
	if _, _, _, err := GetDiskSpace(missing); err == nil {
		t.Fatal("disk space query concealed a missing path")
	}
}

func TestAntigravityProtectionAllowsOnlyRuntimeSubtrees(t *testing.T) {
	for _, tc := range []struct {
		path      string
		protected bool
	}{
		{"/home/test/.gemini", true},
		{"/home/test/.gemini/config/projects/settings.json", true},
		{"/home/test/.gemini/antigravity-cli", true},
		{"/home/test/.gemini/antigravity-cli/brain/session/transcript.jsonl", false},
		{"/home/test/.gemini/antigravity/conversations/session.pb", false},
		{"/home/test/.gemini/antigravity-ide/cache/file", false},
		{"/home/test/.gemini/antigravity-cli/brain/session/auth.json", true},
		{"/home/test/.gemini/antigravity-cli/settings.json", true},
		{"/home/test/.gemini/unrecognized/brain/session", true},
		{"/home/test/.antigravity/config.json", true},
		{"/home/test/.pi/agent/auth.json", true},
		{"/home/test/.pi/agent/models.json", true},
		{"/home/test/.pi/agent/settings.json", true},
		{"/home/test/.pi/agent/sessions/project/session.jsonl", false},
		{".gemini/antigravity-cli/settings.json", true},
		{".pi/agent/models.json", true},
		{".pi/agent/sessions/project/session.jsonl", false},
	} {
		if got := IsProtected(tc.path); got != tc.protected {
			t.Errorf("IsProtected(%q)=%v want %v", tc.path, got, tc.protected)
		}
	}
}

func TestRelativeAndMixedCaseAgentContainers(t *testing.T) {
	for _, path := range []string{".gemini", ".pi", ".pi/agent", ".Gemini/Antigravity-CLI", "/home/test/.PI/Agent"} {
		if !IsAgentContainer(path) || !IsProtected(path) {
			t.Errorf("agent container not protected or traversable: %s", path)
		}
	}
}

func TestHermeticPlatformTrashAdapters(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_item.tmp")
	os.WriteFile(testFile, []byte("data"), 0644)

	binDir := filepath.Join(tmpHome, "bin")
	os.MkdirAll(binDir, 0755)

	if runtime.GOOS == "windows" {
		psScript := filepath.Join(binDir, "powershell.exe")
		os.WriteFile(psScript, []byte("@echo off\nexit 0\n"), 0755)
		t.Setenv("PATH", binDir)

		if err := MoveToTrashOS(testFile); err != nil {
			t.Errorf("MoveToTrashOS Windows mock failed: %v", err)
		}
	} else if runtime.GOOS == "darwin" {
		osascriptFile := filepath.Join(binDir, "osascript")
		os.WriteFile(osascriptFile, []byte("#!/bin/sh\nexit 0\n"), 0755)
		trashFile := filepath.Join(binDir, "trash")
		os.WriteFile(trashFile, []byte("#!/bin/sh\nexit 0\n"), 0755)
		t.Setenv("PATH", binDir)

		if err := MoveToTrashOS(testFile); err != nil {
			t.Errorf("MoveToTrashOS Darwin mock failed: %v", err)
		}
		if err := os.Remove(trashFile); err != nil {
			t.Fatal(err)
		}
		if err := MoveToTrashOS(testFile); err != nil {
			t.Errorf("Finder fallback failed: %v", err)
		}
	} else if runtime.GOOS == "linux" {
		gioScript := filepath.Join(binDir, "gio")
		os.WriteFile(gioScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
		trashScript := filepath.Join(binDir, "trash")
		os.WriteFile(trashScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
		t.Setenv("PATH", binDir)

		if err := MoveToTrashOS(testFile); err != nil {
			t.Errorf("MoveToTrashOS Linux mock gio failed: %v", err)
		}

		os.Remove(gioScript)
		if err := MoveToTrashOS(testFile); err != nil {
			t.Errorf("MoveToTrashOS Linux mock trash failed: %v", err)
		}
	}
}

func TestMoveToTrashOSFallbackWhenNoUtility(t *testing.T) {
	t.Setenv("PATH", "")
	tmpFile := filepath.Join(t.TempDir(), "fallback.tmp")
	os.WriteFile(tmpFile, []byte("data"), 0644)

	if err := MoveToTrashOS(tmpFile); err == nil {
		t.Errorf("Expected MoveToTrashOS to return error when PATH is empty")
	}
}

func TestContainsMountOrReparsePointFailsClosedOnUninspectableSubtree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Chmod 0000 permission test is POSIX specific")
	}

	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "restricted_dir")
	os.MkdirAll(subDir, 0755)

	unreadableChild := filepath.Join(subDir, "secret_child")
	os.MkdirAll(unreadableChild, 0700)
	os.WriteFile(filepath.Join(unreadableChild, "data.bin"), []byte("SECRET"), 0600)

	os.Chmod(unreadableChild, 0000)
	defer os.Chmod(unreadableChild, 0700)

	hasBoundary, _, err := ContainsMountOrReparsePoint(subDir)
	if !hasBoundary {
		t.Errorf("FAIL-CLOSED VIOLATION: Expected ContainsMountOrReparsePoint to return hasBoundary=true on uninspectable subtree; got false")
	}
	if err == nil {
		t.Errorf("Expected ContainsMountOrReparsePoint to return an inspection error on unreadable subtree")
	}
}
