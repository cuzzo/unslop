package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var protectedAgentFilenames = []string{
	"credentials.json", ".credentials", "auth.json", "id_rsa", "id_ed25519", "id_dsa", "secring.gpg",
}

func IsAgentContainer(path string) bool {
	clean := "/" + strings.TrimPrefix(filepath.ToSlash(filepath.Clean(strings.ToLower(path))), "/")
	if strings.HasSuffix(clean, "/.gemini") || strings.HasSuffix(clean, "/.pi") || strings.HasSuffix(clean, "/.pi/agent") {
		return true
	}
	for _, tool := range []string{"antigravity", "antigravity-cli", "antigravity-ide", "antigravity-backup"} {
		if strings.HasSuffix(clean, "/.gemini/"+tool) {
			return true
		}
	}
	return false
}

func IsProtected(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, p := range protectedAgentFilenames {
		if base == p {
			return true
		}
	}
	cleanPath := "/" + strings.TrimPrefix(filepath.ToSlash(filepath.Clean(strings.ToLower(path))), "/")
	if strings.Contains(cleanPath, "/.antigravity") || IsAgentContainer(path) {
		return true
	}
	if _, tail, found := strings.Cut(cleanPath, "/.pi/"); found {
		return tail != "agent/sessions" && !strings.HasPrefix(tail, "agent/sessions/")
	}
	if _, tail, found := strings.Cut(cleanPath, "/.gemini/"); found {
		tool, subtree, _ := strings.Cut(tail, "/")
		if tool == "antigravity" || tool == "antigravity-cli" || tool == "antigravity-ide" || tool == "antigravity-backup" {
			root, _, _ := strings.Cut(subtree, "/")
			switch root {
			case "brain", "conversations", "cache", "implicit", "log", "crashes":
				return false
			}
		}
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
