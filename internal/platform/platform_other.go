//go:build !linux && !darwin && !windows

package platform

import (
	"errors"
	"os"
	"time"
)

func getStatTimes(info os.FileInfo) (time.Time, time.Time, uint32, bool) {
	return info.ModTime(), info.ModTime(), 0, false
}

func getFileIdentity(path string, info os.FileInfo) (uint64, uint64, bool) {
	return 0, 0, false
}

func getDeviceID(dirPath string) (uint64, error) {
	return 0, nil
}

func getDeviceIDFromInfo(fi os.FileInfo) (uint64, error) {
	return 0, nil
}

func getDiskSpaceSyscall(path string) (uint64, uint64, uint64, error) {
	return 100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, nil
}

func moveToTrashOS(path string) error {
	return errors.New("no trash utility on this OS")
}

func LockFile(f *os.File) error {
	return nil
}

func UnlockFile(f *os.File) error {
	return nil
}
