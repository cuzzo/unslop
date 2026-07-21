//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func getStatTimes(info os.FileInfo) (time.Time, time.Time, uint32, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		atime := time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
		ctime := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		return atime, ctime, stat.Uid, true
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
	if gioBin, err := exec.LookPath("gio"); err == nil {
		if err := exec.Command(gioBin, "trash", path).Run(); err == nil {
			return nil
		}
	}
	if trashBin, err := exec.LookPath("trash"); err == nil {
		if err := exec.Command(trashBin, path).Run(); err == nil {
			return nil
		}
	}
	return errors.New("no desktop trash utility")
}
