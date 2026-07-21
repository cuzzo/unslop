//go:build windows

package main

import (
	"os"
	"time"
)

func getStatTimes(info os.FileInfo) (atime time.Time, ctime time.Time, uid int, isPosix bool) {
	return info.ModTime(), info.ModTime(), 0, false
}

func getDiskSpaceSyscall(path string) (uint64, uint64, uint64, error) {
	return 100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, nil
}
