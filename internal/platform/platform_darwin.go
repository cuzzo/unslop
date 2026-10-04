//go:build darwin

package platform

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func GetStatTimes(info os.FileInfo) (time.Time, time.Time, uint32, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		atime := time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
		ctime := time.Unix(stat.Ctimespec.Sec, stat.Ctimespec.Nsec)
		return atime, ctime, uint32(stat.Uid), true
	}
	return info.ModTime(), info.ModTime(), 0, false
}

func MoveToTrashOS(path string) error {
	if trashBin, err := exec.LookPath("trash"); err == nil {
		if err := exec.Command(trashBin, path).Run(); err == nil {
			return nil
		}
	}
	return exec.Command("osascript", "-e", "on run argv", "-e", "tell application \"Finder\" to delete POSIX file (item 1 of argv)", "-e", "end run", path).Run()
}
