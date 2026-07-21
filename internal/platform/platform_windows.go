//go:build windows

package platform

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

type byHandleFileInformation struct {
	dwFileAttributes     uint32
	ftCreationTime       syscall.Filetime
	ftLastAccessTime     syscall.Filetime
	ftLastWriteTime      syscall.Filetime
	dwVolumeSerialNumber uint32
	nFileSizeHigh        uint32
	nFileSizeLow         uint32
	nNumberOfLinks       uint32
	nFileIndexHigh       uint32
	nFileIndexLow        uint32
}

func getFileIdentity(path string, info os.FileInfo) (uint64, uint64, bool) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, false
	}
	handle, err := syscall.CreateFile(
		pathPtr,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return 0, 0, false
	}
	defer syscall.CloseHandle(handle)

	var fileInfo byHandleFileInformation
	r1, _, _ := procGetFileInformationByHandle.Call(uintptr(handle), uintptr(unsafe.Pointer(&fileInfo)))
	if r1 == 0 {
		return 0, 0, false
	}

	vol := uint64(fileInfo.dwVolumeSerialNumber)
	fileIndex := (uint64(fileInfo.nFileIndexHigh) << 32) | uint64(fileInfo.nFileIndexLow)
	return vol, fileIndex, true
}

func getDeviceID(dirPath string) (uint64, error) {
	return 0, nil
}

func getDeviceIDFromInfo(fi os.FileInfo) (uint64, error) {
	return 0, nil
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
	script := `param($p); Add-Type -AssemblyName Microsoft.VisualBasic; if (Test-Path -LiteralPath $p -PathType Container) { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p, 'OnlyErrorDialogs', 'SendToRecycleBin') } else { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p, 'OnlyErrorDialogs', 'SendToRecycleBin') }`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script, path)
	return cmd.Run()
}

var (
	modkernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx                 = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx               = modkernel32.NewProc("UnlockFileEx")
	procGetFileInformationByHandle = modkernel32.NewProc("GetFileInformationByHandle")
)

const (
	LOCKFILE_EXCLUSIVE_LOCK = 2
)

func LockFile(f *os.File) error {
	var ol syscall.Overlapped
	r1, _, err := procLockFileEx.Call(
		f.Fd(),
		uintptr(LOCKFILE_EXCLUSIVE_LOCK),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return err
		}
		return syscall.EINVAL
	}
	return nil
}

func UnlockFile(f *os.File) error {
	var ol syscall.Overlapped
	r1, _, err := procUnlockFileEx.Call(
		f.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return err
		}
		return syscall.EINVAL
	}
	return nil
}
