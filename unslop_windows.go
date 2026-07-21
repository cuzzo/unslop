//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

func getStatTimes(info os.FileInfo) (time.Time, time.Time, uint32, bool) {
	return info.ModTime(), info.ModTime(), 0, false
}

func getDiskSpaceSyscall(path string) (uint64, uint64, uint64, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, 0, err
	}

	r1, _, errNo := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
	)
	if r1 == 0 {
		return 0, 0, 0, errNo
	}

	used := totalNumberOfBytes - totalNumberOfFreeBytes
	return totalNumberOfBytes, used, totalNumberOfFreeBytes, nil
}

func moveToTrashOS(path string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "param($p); Remove-Item -LiteralPath $p -Recycle -Force", path)
	return cmd.Run()
}
