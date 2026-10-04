package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/format"
	"github.com/yahn/unslop/internal/platform"
)

type Candidate struct {
	Path         string           `json:"path"`
	Size         int64            `json:"size_bytes"`
	AgeDays      float64          `json:"age_days"`
	Category     string           `json:"category"`
	RiskClass    config.RiskClass `json:"risk_class"`
	CanDelete    bool             `json:"can_delete"`
	IsDir        bool             `json:"is_dir"`
	ModTime      time.Time        `json:"mod_time"`
	RootModTime  time.Time        `json:"root_mod_time"`
	DeviceID     uint64           `json:"device_id,omitempty"`
	InodeNum     uint64           `json:"inode_num,omitempty"`
	HasIdentity  bool             `json:"has_identity,omitempty"`
	IsGitIgnored bool             `json:"is_gitignore,omitempty"`
	IsDevBinary  bool             `json:"is_dev_binary,omitempty"`
}

func GetDefaultScanDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return []string{"."}
	}
	return []string{home, os.TempDir()}
}

func IsPackageRegistryInternalPath(path string) bool {
	pathClean := filepath.ToSlash(path)
	return strings.Contains(pathClean, "/.cargo/registry/") ||
		strings.Contains(pathClean, "/.cargo/git/") ||
		strings.Contains(pathClean, "/.local/pipx/") ||
		strings.Contains(pathClean, "/.npm/") ||
		strings.Contains(pathClean, "/.cache/pypoetry/") ||
		strings.Contains(pathClean, "/.cache/yarn/") ||
		strings.Contains(pathClean, "/.gradle/caches/")
}

func GetEffectiveItemTime(info os.FileInfo) time.Time {
	mtime := info.ModTime()
	if mtime.Before(time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)) {
		atime, ctime, _, isPosix := platform.GetStatTimes(info)
		if isPosix {
			best := mtime
			if !atime.IsZero() && atime.After(best) {
				best = atime
			}
			if !ctime.IsZero() && ctime.After(best) {
				best = ctime
			}
			return best
		}
	}
	return mtime
}

func IsExecutableBinary(path string, info os.FileInfo) bool {
	if info.IsDir() {
		return false
	}

	name := strings.ToLower(info.Name())
	ext := filepath.Ext(name)

	switch ext {
	case ".exe", ".out", ".dylib", ".so", ".dll", ".o", ".a", ".elf":
		return true
	}

	if info.Mode()&0111 != 0 {
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer f.Close()

		buf := make([]byte, 4)
		n, err := f.Read(buf)
		if err != nil || n < 2 {
			return false
		}

		if buf[0] == '#' && buf[1] == '!' {
			return false
		}

		if n >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
			return true
		}
		if n >= 4 {
			if (buf[0] == 0xfe && buf[1] == 0xed && buf[2] == 0xfa && (buf[3] == 0xce || buf[3] == 0xcf)) ||
				(buf[0] == 0xce && buf[1] == 0xfa && buf[2] == 0xed && buf[3] == 0xfe) ||
				(buf[0] == 0xcf && buf[1] == 0xfa && buf[2] == 0xed && buf[3] == 0xfe) ||
				(buf[0] == 0xca && buf[1] == 0xfe && buf[2] == 0xba && buf[3] == 0xbe) {
				return true
			}
		}
		if buf[0] == 'M' && buf[1] == 'Z' {
			return true
		}
		if n >= 4 && buf[0] == 0x00 && buf[1] == 'a' && buf[2] == 's' && buf[3] == 'm' {
			return true
		}
	}

	return false
}

func InspectSubtree(ctx context.Context, dirPath string, now time.Time) (size int64, maxModTime time.Time, fileCount int64, hasProtected bool, err error) {
	fi, errLstat := os.Lstat(dirPath)
	if errLstat != nil {
		return 0, now, 0, true, errLstat
	}
	maxModTime = fi.ModTime()

	if platform.IsProtected(dirPath) {
		hasProtected = true
	}

	var walkErr error
	errWalk := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if ctx.Err() != nil {
			walkErr = ctx.Err()
			return filepath.SkipAll
		}
		if err != nil {
			walkErr = err
			hasProtected = true
			return filepath.SkipAll
		}
		if platform.IsProtected(path) {
			hasProtected = true
		}

		fileCount++

		info, errInfo := d.Info()
		if errInfo != nil {
			walkErr = errInfo
			hasProtected = true
			return filepath.SkipAll
		}

		size += info.Size()

		effTime := GetEffectiveItemTime(info)
		if effTime.After(maxModTime) {
			maxModTime = effTime
		}
		return nil
	})

	if errWalk != nil && walkErr == nil {
		walkErr = errWalk
	}

	return size, maxModTime, fileCount, hasProtected, walkErr
}

func ScanParallelChecked(scanDirs []string, engine *config.RuleEngine, minDays float64, maxDays float64, minSizeBytes int64, includeData bool) ([]Candidate, error) {
	return ScanLive(context.Background(), scanDirs, engine, minDays, maxDays, minSizeBytes, includeData, os.Stderr, nil)
}

type Progress struct {
	Candidates       []Candidate
	Completed, Total int64
	Files            int64
	Done             bool
}

func ScanLive(ctx context.Context, scanDirs []string, engine *config.RuleEngine, minDays float64, maxDays float64, minSizeBytes int64, includeData bool, diagnostics io.Writer, update func(Progress)) ([]Candidate, error) {
	var scanErrors int64
	var errorMu sync.Mutex
	reportError := func(path string, err error) {
		errorMu.Lock()
		defer errorMu.Unlock()
		scanErrors++
		fmt.Fprintf(diagnostics, "[SCAN ERROR] %q: %v\n", path, err)
	}

	var topLevelPaths []string
	for _, root := range scanDirs {
		if ctx.Err() != nil {
			break
		}
		p := root
		if strings.HasPrefix(root, "~") {
			home, _ := os.UserHomeDir()
			p = filepath.Join(home, root[1:])
		}
		p = filepath.Clean(p)
		fi, err := os.Stat(p)
		if err != nil {
			reportError(p, err)
			continue
		}
		if !fi.IsDir() {
			topLevelPaths = append(topLevelPaths, p)
			continue
		}

		if rule := engine.Match(fi.Name(), p, true); rule != nil {
			topLevelPaths = append(topLevelPaths, p)
			continue
		}

		entries, err := os.ReadDir(p)
		if err != nil {
			topLevelPaths = append(topLevelPaths, p)
			continue
		}
		for _, e := range entries {
			topLevelPaths = append(topLevelPaths, filepath.Join(p, e.Name()))
		}
	}

	var walkWg sync.WaitGroup
	currentUID := uint32(os.Getuid())

	var scannedFiles int64
	var candidateBytes int64

	var candidates []Candidate
	var candMu sync.Mutex
	var completed atomic.Int64

	now := time.Now()
	startTime := now

	doneProgress := make(chan struct{})
	progressFinished := make(chan struct{})
	go func() {
		defer close(progressFinished)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			done := false
			select {
			case <-doneProgress:
				done = true
			case <-ticker.C:
			}
			candMu.Lock()
			cCount, cBytes := len(candidates), candidateBytes
			var snapshot []Candidate
			if update != nil {
				snapshot = append([]Candidate{}, candidates...)
			}
			candMu.Unlock()
			sFiles := atomic.LoadInt64(&scannedFiles)
			elapsedSec := time.Since(startTime).Seconds()
			if update != nil {
				update(Progress{Candidates: snapshot, Completed: completed.Load(), Total: int64(len(topLevelPaths)), Files: sFiles, Done: done})
			} else if done {
				fmt.Fprintf(os.Stderr, "\r\033[KScanning complete | %s files in %.1fs | Candidates: %d (%s)\n",
					format.FormatNumber(sFiles), elapsedSec, cCount, format.FormatBytes(cBytes))
			} else {
				filesPerSec := 0.0
				if elapsedSec > 0 {
					filesPerSec = float64(sFiles) / elapsedSec
				}
				fmt.Fprintf(os.Stderr, "\r\033[KScanning... %s files (%.0f/s) | Candidates: %d (%s)",
					format.FormatNumber(sFiles), filesPerSec, cCount, format.FormatBytes(cBytes))
			}
			if done {
				return
			}
		}
	}()

	sem := make(chan struct{}, 16)

	for _, targetPath := range topLevelPaths {
		walkWg.Add(1)
		go func(r string) {
			defer walkWg.Done()
			defer completed.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			tmp := filepath.Clean(os.TempDir())
			isTmp := r == tmp || strings.HasPrefix(r, tmp+string(filepath.Separator))

			_ = filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
				if ctx.Err() != nil {
					return filepath.SkipAll
				}
				if err != nil {
					reportError(p, err)
					return nil
				}
				name := d.Name()

				if strings.Contains(name, ".unslop-quarantine-") {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if platform.IsProtected(p) && !platform.IsAgentContainer(p) {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if d.IsDir() && (name == ".git" || name == ".hg" || name == ".svn") {
					return filepath.SkipDir
				}

				if isTmp {
					if info, err := d.Info(); err == nil {
						_, _, uid, isPosix := platform.GetStatTimes(info)
						if isPosix && uid != currentUID {
							if d.IsDir() {
								return filepath.SkipDir
							}
							return nil
						}
					}
				}

				cand := Candidate{Path: p, IsDir: d.IsDir()}
				var rule *config.Rule
				var info os.FileInfo
				hasProtected := false
				if cand.IsDir {
					rule = engine.Match(name, p, true)
					if rule == nil {
						atomic.AddInt64(&scannedFiles, 1)
						return nil
					}
					if rule.RiskClass == config.RiskUserData && !includeData {
						return filepath.SkipDir
					}
					var inspectErr error
					var fileCount int64
					cand.Size, cand.ModTime, fileCount, hasProtected, inspectErr = InspectSubtree(ctx, p, now)
					if inspectErr != nil && ctx.Err() == nil {
						reportError(p, inspectErr)
					}
					if rootInfo, err := d.Info(); err == nil {
						cand.RootModTime = rootInfo.ModTime()
						cand.DeviceID, cand.InodeNum, cand.HasIdentity = platform.GetFileIdentity(p, rootInfo)
					}
					atomic.AddInt64(&scannedFiles, fileCount)
				} else {
					atomic.AddInt64(&scannedFiles, 1)
					if IsPackageRegistryInternalPath(p) {
						return nil
					}
					info, err = d.Info()
					if err != nil {
						return nil
					}
					rule = engine.Match(name, p, false)
					if rule == nil || (rule.RiskClass == config.RiskUserData && !includeData) {
						return nil
					}
					cand.Size, cand.ModTime = info.Size(), GetEffectiveItemTime(info)
					cand.RootModTime = cand.ModTime
					cand.DeviceID, cand.InodeNum, cand.HasIdentity = platform.GetFileIdentity(p, info)
				}
				cand.AgeDays = now.Sub(cand.ModTime).Hours() / 24
				if !cand.IsDir && cand.AgeDays < 0 {
					cand.AgeDays = 0
				}
				reqMinSize := minSizeBytes
				if rule.MinSizeMB > 0 {
					reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
				}
				if cand.AgeDays >= minDays && (maxDays <= 0 || cand.AgeDays <= maxDays) && cand.Size >= reqMinSize {
					cand.Category, cand.RiskClass = rule.Category, rule.RiskClass
					cand.CanDelete = canDeleteCandidate(rule.RiskClass, includeData, hasProtected)
					cand.IsGitIgnored = checkPathIgnored(p)
					cand.IsDevBinary = rule.ID == "dev_binaries" || rule.Category == "Dev Binary" || rule.Category == "Development Binary"
					if !cand.IsDir {
						cand.IsDevBinary = cand.IsDevBinary || IsExecutableBinary(p, info)
					}
					candMu.Lock()
					candidates = append(candidates, cand)
					candidateBytes += cand.Size
					candMu.Unlock()
					if cand.IsDir {
						return filepath.SkipDir
					}
				}
				if cand.IsDir {
					if rule.RiskClass == config.RiskUserData {
						return filepath.SkipDir
					}
					atomic.AddInt64(&scannedFiles, 1)
				}
				return nil
			})
		}(targetPath)
	}

	walkWg.Wait()
	close(doneProgress)
	<-progressFinished
	if count := scanErrors; count > 0 {
		return candidates, fmt.Errorf("scan incomplete: %d filesystem errors; check access permissions", count)
	}
	if ctx.Err() != nil {
		return candidates, ctx.Err()
	}
	return candidates, nil
}

func canDeleteCandidate(risk config.RiskClass, includeData, containsProtected bool) bool {
	return !containsProtected && (risk == config.RiskRegenerable || (risk == config.RiskUserData && includeData))
}

func checkPathIgnored(candPath string) bool {
	dir := filepath.Dir(candPath)
	candBase := filepath.Base(candPath)

	for {
		ignoreFiles := []string{
			filepath.Join(dir, ".unslopignore"),
			filepath.Join(dir, ".gitignore"),
		}

		for _, igPath := range ignoreFiles {
			if data, err := os.ReadFile(igPath); err == nil {
				lines := strings.Split(string(data), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					line = strings.TrimPrefix(line, "/")
					line = strings.TrimSuffix(line, "/")

					if line == candBase {
						return true
					}
					if matched, _ := filepath.Match(line, candBase); matched {
						return true
					}
				}
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir || dir == "/" || dir == "." {
			break
		}
		dir = parent
	}

	return false
}
