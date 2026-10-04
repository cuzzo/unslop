//go:build linux

package platform

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func GetStatTimes(info os.FileInfo) (time.Time, time.Time, uint32, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		atime := time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
		ctime := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
		return atime, ctime, stat.Uid, true
	}
	return info.ModTime(), info.ModTime(), 0, false
}

func MoveToTrashOS(path string) error {
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
