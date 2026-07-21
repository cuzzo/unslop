//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"
)

func getStatTimes(info os.FileInfo) (atime time.Time, ctime time.Time, uid int, isPosix bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		atime = time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
		ctime = time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		uid = int(stat.Uid)
		return atime, ctime, uid, true
	}
	return info.ModTime(), info.ModTime(), 0, false
}

func getDiskSpaceSyscall(path string) (uint64, uint64, uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, 0, 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free
	return total, used, free, nil
}
