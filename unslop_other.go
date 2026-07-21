//go:build !linux && !darwin && !windows

package main

import (
	"errors"
	"os"
	"time"
)

func getStatTimes(info os.FileInfo) (time.Time, time.Time, uint32, bool) {
	return info.ModTime(), info.ModTime(), 0, false
}

func getDiskSpaceSyscall(path string) (uint64, uint64, uint64, error) {
	return 100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, nil
}

func moveToTrashOS(path string) error {
	return errors.New("no trash utility on this OS")
}
