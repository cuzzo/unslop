package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var protectedAgentFilenames = []string{
	"credentials.json", ".credentials", "auth.json", "id_rsa", "id_ed25519", "id_dsa", "secring.gpg",
}

func IsProtected(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, p := range protectedAgentFilenames {
		if base == p {
			return true
		}
	}
	cleanPath := filepath.ToSlash(strings.ToLower(path))
	if strings.Contains(cleanPath, "/.gemini/") || strings.Contains(cleanPath, "/.antigravity") {
		return true
	}
	return false
}

func ContainsProtectedPath(targetPath string) bool {
	var foundProtected bool
	err := filepath.WalkDir(targetPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			foundProtected = true
			return filepath.SkipAll
		}
		if IsProtected(p) {
			foundProtected = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return true
	}
	return foundProtected
}

func GetDiskSpace(path string) (totalBytes, usedBytes, freeBytes uint64, err error) {
	return getDiskSpaceSyscall(path)
}

func MoveToTrashOS(path string) error {
	return moveToTrashOS(path)
}

func GetStatTimes(info os.FileInfo) (atime, ctime time.Time, uid uint32, isPosix bool) {
	return getStatTimes(info)
}

func GetFileIdentity(path string, info os.FileInfo) (dev uint64, ino uint64, supported bool) {
	return getFileIdentity(path, info)
}

func ContainsMountOrReparsePoint(dirPath string) (bool, string, error) {
	rootDev, err := getDeviceID(dirPath)
	if err != nil {
		return true, dirPath, fmt.Errorf("failed to get root device ID for %s: %w", dirPath, err)
	}

	var boundaryPath string
	var boundaryErr error

	errWalk := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			boundaryPath = path
			boundaryErr = fmt.Errorf("uninspectable path during boundary scan (%s): %w", path, err)
			return filepath.SkipAll
		}
		if path == dirPath {
			return nil
		}

		fi, errInfo := d.Info()
		if errInfo != nil {
			boundaryPath = path
			boundaryErr = fmt.Errorf("uninspectable file info during boundary scan (%s): %w", path, errInfo)
			return filepath.SkipAll
		}

		if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 {
			boundaryPath = path
			boundaryErr = fmt.Errorf("reparse point or symlink boundary detected at %s", path)
			return filepath.SkipDir
		}

		if rootDev != 0 {
			dev, errDev := getDeviceIDFromInfo(fi)
			if errDev != nil {
				boundaryPath = path
				boundaryErr = fmt.Errorf("failed to check device ID for %s: %w", path, errDev)
				return filepath.SkipAll
			}
			if dev != 0 && dev != rootDev {
				boundaryPath = path
				boundaryErr = fmt.Errorf("mount point boundary detected at %s (device ID %d != %d)", path, dev, rootDev)
				return filepath.SkipDir
			}
		}

		return nil
	})

	if boundaryPath != "" {
		return true, boundaryPath, boundaryErr
	}

	if errWalk != nil {
		return true, dirPath, errWalk
	}

	return false, "", nil
}
