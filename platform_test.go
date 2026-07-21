package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHermeticPlatformTrashAdapters(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_item.tmp")
	os.WriteFile(testFile, []byte("data"), 0644)

	// Mock injected command environment
	binDir := filepath.Join(tmpHome, "bin")
	os.MkdirAll(binDir, 0755)

	if runtime.GOOS == "windows" {
		psScript := filepath.Join(binDir, "powershell.exe")
		os.WriteFile(psScript, []byte("@echo off\nexit 0\n"), 0755)
		t.Setenv("PATH", binDir)

		if err := moveToTrashOS(testFile); err != nil {
			t.Errorf("moveToTrashOS Windows mock failed: %v", err)
		}
	} else if runtime.GOOS == "darwin" {
		osascriptFile := filepath.Join(binDir, "osascript")
		os.WriteFile(osascriptFile, []byte("#!/bin/sh\nexit 0\n"), 0755)
		trashFile := filepath.Join(binDir, "trash")
		os.WriteFile(trashFile, []byte("#!/bin/sh\nexit 0\n"), 0755)
		t.Setenv("PATH", binDir)

		if err := moveToTrashOS(testFile); err != nil {
			t.Errorf("moveToTrashOS Darwin mock failed: %v", err)
		}
	} else if runtime.GOOS == "linux" {
		gioScript := filepath.Join(binDir, "gio")
		os.WriteFile(gioScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
		trashScript := filepath.Join(binDir, "trash")
		os.WriteFile(trashScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
		t.Setenv("PATH", binDir)

		if err := moveToTrashOS(testFile); err != nil {
			t.Errorf("moveToTrashOS Linux mock gio failed: %v", err)
		}

		os.Remove(gioScript)
		if err := moveToTrashOS(testFile); err != nil {
			t.Errorf("moveToTrashOS Linux mock trash failed: %v", err)
		}
	}
}

func TestMoveToTrashOSFallbackWhenNoUtility(t *testing.T) {
	t.Setenv("PATH", "")
	tmpFile := filepath.Join(t.TempDir(), "fallback.tmp")
	os.WriteFile(tmpFile, []byte("data"), 0644)

	// moveToTrashOS returns error when no OS trash binary is in PATH
	if err := moveToTrashOS(tmpFile); err == nil {
		t.Errorf("Expected moveToTrashOS to return error when PATH is empty")
	}
}
