//go:build darwin

package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func getStatTimes(info os.FileInfo) (time.Time, time.Time, uint32, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		atime := time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
		ctime := time.Unix(stat.Ctimespec.Sec, stat.Ctimespec.Nsec)
		return atime, ctime, uint32(stat.Uid), true
	}
	return info.ModTime(), info.ModTime(), 0, false
}

func getDiskSpaceSyscall(path string) (uint64, uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	return total, used, free, nil
}

func moveToTrashOS(path string) error {
	if trashBin, err := exec.LookPath("trash"); err == nil {
		if err := exec.Command(trashBin, path).Run(); err == nil {
			return nil
		}
	}
	return exec.Command("osascript", "-e", "on run argv", "-e", "tell application \"Finder\" to delete POSIX file (item 1 of argv)", "-e", "end run", path).Run()
}
