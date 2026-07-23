package scanner

import (
	"fmt"
	"os"
	"os/exec"
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
	ID             int              `json:"id"`
	Path           string           `json:"path"`
	Size           int64            `json:"size_bytes"`
	AgeDays        float64          `json:"age_days"`
	Category       string           `json:"category"`
	RuleID         string           `json:"rule_id"`
	RiskClass      config.RiskClass `json:"risk_class"`
	Reason         string           `json:"reason"`
	Evidence       string           `json:"evidence"`
	ProposedAction string           `json:"proposed_action"`
	CanDelete      bool             `json:"can_delete"`
	IsDir          bool             `json:"is_dir"`
	FileCount      int64            `json:"file_count"`
	PackageName    string           `json:"package_name,omitempty"`
	UninstallArgs  []string         `json:"uninstall_args,omitempty"`
	ModTime        time.Time        `json:"mod_time"`
	RootModTime    time.Time        `json:"root_mod_time"`
	DeviceID       uint64           `json:"device_id,omitempty"`
	InodeNum       uint64           `json:"inode_num,omitempty"`
	HasIdentity    bool             `json:"has_identity,omitempty"`
	IsGitIgnored   bool             `json:"is_gitignore,omitempty"`
	IsDevBinary    bool             `json:"is_dev_binary,omitempty"`
}

type PackageInventory struct {
	CargoPkgs    map[string]string
	NpmPkgs      map[string]string
	PipxPkgs     map[string]string
	DotnetTools  map[string]string
	ComposerPkgs map[string]string
	ZvmVersions  map[string]string
}

func LoadPackageInventory() *PackageInventory {
	inv := &PackageInventory{
		CargoPkgs:    make(map[string]string),
		NpmPkgs:      make(map[string]string),
		PipxPkgs:     make(map[string]string),
		DotnetTools:  make(map[string]string),
		ComposerPkgs: make(map[string]string),
		ZvmVersions:  make(map[string]string),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(6)

	go func() {
		defer wg.Done()
		if cargoBin, err := exec.LookPath("cargo"); err == nil {
			out, err := exec.Command(cargoBin, "install", "--list").Output()
			if err == nil {
				pkgs := parseCargoListOutput(string(out))
				mu.Lock()
				for _, p := range pkgs {
					inv.CargoPkgs[p] = p
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if npmBin, err := exec.LookPath("npm"); err == nil {
			out, err := exec.Command(npmBin, "list", "-g", "--depth=0").Output()
			if err == nil {
				pkgs := parseNpmListOutput(string(out))
				mu.Lock()
				for _, p := range pkgs {
					inv.NpmPkgs[p] = p
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if pipxBin, err := exec.LookPath("pipx"); err == nil {
			out, err := exec.Command(pipxBin, "list").Output()
			if err == nil {
				pkgs := parsePipxListOutput(string(out))
				mu.Lock()
				for _, p := range pkgs {
					inv.PipxPkgs[p] = p
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if dotnetBin, err := exec.LookPath("dotnet"); err == nil {
			out, err := exec.Command(dotnetBin, "tool", "list", "-g").Output()
			if err == nil {
				pkgs := parseDotnetToolListOutput(string(out))
				mu.Lock()
				for _, p := range pkgs {
					inv.DotnetTools[p] = p
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if composerBin, err := exec.LookPath("composer"); err == nil {
			out, err := exec.Command(composerBin, "global", "show", "--direct").Output()
			if err == nil {
				pkgs := parseComposerShowOutput(string(out))
				mu.Lock()
				for _, p := range pkgs {
					inv.ComposerPkgs[p] = p
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if zvmBin, err := exec.LookPath("zvm"); err == nil {
			out, err := exec.Command(zvmBin, "ls").Output()
			if err == nil {
				pkgs := parseZvmLsOutput(string(out))
				mu.Lock()
				for _, p := range pkgs {
					inv.ZvmVersions[p] = p
				}
				mu.Unlock()
			}
		}
	}()

	wg.Wait()
	return inv
}

func parseCargoListOutput(out string) []string {
	var pkgs []string
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if len(l) > 0 && !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") && strings.Contains(l, " v") {
			parts := strings.Fields(l)
			if len(parts) >= 1 {
				pkgs = append(pkgs, parts[0])
			}
		}
	}
	return pkgs
}

func parseNpmListOutput(out string) []string {
	var pkgs []string
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if strings.Contains(l, "── ") {
			idx := strings.Index(l, "── ")
			pkgStr := strings.TrimSpace(l[idx+len("── "):])
			if atIdx := strings.LastIndex(pkgStr, "@"); atIdx > 0 {
				pkgs = append(pkgs, pkgStr[:atIdx])
			} else {
				pkgs = append(pkgs, pkgStr)
			}
		}
	}
	return pkgs
}

func parsePipxListOutput(out string) []string {
	var pkgs []string
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "package ") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				pkgs = append(pkgs, parts[1])
			}
		}
	}
	return pkgs
}

func parseDotnetToolListOutput(out string) []string {
	var pkgs []string
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if i < 2 {
			continue
		}
		parts := strings.Fields(l)
		if len(parts) >= 1 {
			pkgs = append(pkgs, parts[0])
		}
	}
	return pkgs
}

func parseComposerShowOutput(out string) []string {
	var pkgs []string
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		parts := strings.Fields(l)
		if len(parts) >= 1 && strings.Contains(parts[0], "/") {
			pkgs = append(pkgs, parts[0])
		}
	}
	return pkgs
}

func parseZvmLsOutput(out string) []string {
	var pkgs []string
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		l = strings.TrimPrefix(l, "*")
		l = strings.TrimSpace(l)
		if len(l) > 0 {
			pkgs = append(pkgs, l)
		}
	}
	return pkgs
}

func GetDefaultScanDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return []string{"."}
	}
	return []string{home, "/tmp"}
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
	if name == "a.out" {
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

func inspectDirectorySubtree(dirPath string, now time.Time) (size int64, maxModTime time.Time, fileCount int64, hasProtected bool, err error) {
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
			return nil
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

func countFilesInSubtree(dirPath string) int64 {
	var count int64
	_ = filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		count++
		return nil
	})
	return count
}

func ScanParallel(scanDirs []string, engine *config.RuleEngine, minDays float64, maxDays float64, minSizeBytes int64, includeData bool) []Candidate {
	pkgInventory := LoadPackageInventory()
	_ = pkgInventory

	var topLevelPaths []string
	for _, root := range scanDirs {
		p := root
		if strings.HasPrefix(root, "~") {
			home, _ := os.UserHomeDir()
			p = filepath.Join(home, root[1:])
		}
		p = filepath.Clean(p)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !fi.IsDir() {
			topLevelPaths = append(topLevelPaths, p)
			continue
		}

		pkgInvMap := make(map[string]string)
		if rule, _, _ := engine.MatchDir(fi.Name(), p, pkgInvMap); rule != nil {
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
	var candidateCount int64
	var candidateBytes int64

	var candidates []Candidate
	var candMu sync.Mutex

	now := time.Now()
	startTime := now

	doneProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-doneProgress:
				sFiles := atomic.LoadInt64(&scannedFiles)
				cBytes := atomic.LoadInt64(&candidateBytes)
				cCount := atomic.LoadInt64(&candidateCount)
				elapsedSec := time.Since(startTime).Seconds()
				fmt.Fprintf(os.Stderr, "\r\033[KScanning complete | %s files in %.1fs | Candidates: %d (%s)\n",
					format.FormatNumber(sFiles), elapsedSec, cCount, format.FormatBytes(cBytes))
				return
			case <-ticker.C:
				sFiles := atomic.LoadInt64(&scannedFiles)
				cBytes := atomic.LoadInt64(&candidateBytes)
				cCount := atomic.LoadInt64(&candidateCount)

				elapsedSec := time.Since(startTime).Seconds()
				filesPerSec := 0.0
				if elapsedSec > 0 {
					filesPerSec = float64(sFiles) / elapsedSec
				}

				fmt.Fprintf(os.Stderr, "\r\033[KScanning... %s files (%.0f/s) | Candidates: %d (%s)",
					format.FormatNumber(sFiles), filesPerSec, cCount, format.FormatBytes(cBytes))
			}
		}
	}()

	sem := make(chan struct{}, 16)

	for _, targetPath := range topLevelPaths {
		walkWg.Add(1)
		go func(r string) {
			defer walkWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			isTmp := r == "/tmp" || strings.HasPrefix(r, "/tmp/")

			_ = filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				name := d.Name()

				if strings.Contains(name, ".unslop-quarantine-") {
					if d.IsDir() {
						atomic.AddInt64(&scannedFiles, countFilesInSubtree(p))
						return filepath.SkipDir
					}
					return nil
				}

				if platform.IsProtected(p) {
					if d.IsDir() {
						atomic.AddInt64(&scannedFiles, countFilesInSubtree(p))
						return filepath.SkipDir
					}
					return nil
				}

				if d.IsDir() && (name == ".git" || name == ".hg" || name == ".svn") {
					atomic.AddInt64(&scannedFiles, countFilesInSubtree(p))
					return filepath.SkipDir
				}

				if isTmp {
					if info, err := d.Info(); err == nil {
						_, _, uid, isPosix := platform.GetStatTimes(info)
						if isPosix && uid != currentUID {
							if d.IsDir() {
								atomic.AddInt64(&scannedFiles, countFilesInSubtree(p))
								return filepath.SkipDir
							}
							return nil
						}
					}
				}

				if d.IsDir() {
					pkgInvMap := make(map[string]string)
					rule, pkgName, uninstallArgs := engine.MatchDir(name, p, pkgInvMap)
					if rule != nil {
						if rule.RiskClass == config.RiskUserData && !includeData {
							atomic.AddInt64(&scannedFiles, countFilesInSubtree(p))
							return filepath.SkipDir
						}
						sz, maxModTime, fCount, hasProt, _ := inspectDirectorySubtree(p, now)
						act, canDel := determineCandidateAction(rule, true, uninstallArgs, includeData, hasProt)

						rootFi, errStat := d.Info()
						var rootModTime time.Time
						var devId, inoNum uint64
						var hasId bool
						if errStat == nil {
							rootModTime = rootFi.ModTime()
							devId, inoNum, hasId = platform.GetFileIdentity(p, rootFi)
						}

						atomic.AddInt64(&scannedFiles, fCount)

						ageDays := now.Sub(maxModTime).Hours() / 24.0

						reqMinSize := minSizeBytes
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}

						validMinAge := ageDays >= minDays
						validMaxAge := maxDays <= 0 || ageDays <= maxDays

						if validMinAge && validMaxAge && sz >= reqMinSize {
							cand := Candidate{
								Path:           p,
								Size:           sz,
								AgeDays:        ageDays,
								Category:       rule.Category,
								RuleID:         rule.ID,
								RiskClass:      rule.RiskClass,
								Reason:         fmt.Sprintf("%s (stale for %.1fd, %s)", rule.Name, ageDays, format.FormatBytes(sz)),
								Evidence:       fmt.Sprintf("Size: %s, Age: %.1fd, Files: %d", format.FormatBytes(sz), ageDays, fCount),
								ProposedAction: act,
								CanDelete:      canDel,
								IsDir:          true,
								FileCount:      fCount,
								PackageName:    pkgName,
								UninstallArgs:  uninstallArgs,
								ModTime:        maxModTime,
								RootModTime:    rootModTime,
								DeviceID:       devId,
								InodeNum:       inoNum,
								HasIdentity:    hasId,
								IsGitIgnored:   checkPathIgnored(p),
								IsDevBinary:    rule.ID == "dev_binaries" || rule.Category == "Dev Binary" || rule.Category == "Development Binary",
							}

							candMu.Lock()
							cand.ID = len(candidates) + 1
							candidates = append(candidates, cand)
							candMu.Unlock()

							atomic.AddInt64(&candidateCount, 1)
							atomic.AddInt64(&candidateBytes, sz)

							return filepath.SkipDir
						}
					}
				}

				atomic.AddInt64(&scannedFiles, 1)

				if !d.IsDir() {
					if IsPackageRegistryInternalPath(p) {
						return nil
					}
					info, err := d.Info()
					if err != nil {
						return nil
					}
					sz := info.Size()

					pkgInvMap := make(map[string]string)
					rule, pkgName, uninstallArgs := engine.MatchFile(name, p, info, pkgInvMap)
					if rule != nil {
						if rule.RiskClass == config.RiskUserData && !includeData {
							return nil
						}

						reqMinSize := minSizeBytes
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}
						if sz < reqMinSize {
							return nil
						}

						act, canDel := determineCandidateAction(rule, false, uninstallArgs, includeData, false)

						lastActivity := GetEffectiveItemTime(info)
						ageDays := now.Sub(lastActivity).Hours() / 24.0
						if ageDays < 0 {
							ageDays = 0
						}

						devId, inoNum, hasId := platform.GetFileIdentity(p, info)

						validMinAge := ageDays >= minDays
						validMaxAge := maxDays <= 0 || ageDays <= maxDays

						if validMinAge && validMaxAge && sz >= reqMinSize {
							cand := Candidate{
								Path:           p,
								Size:           sz,
								AgeDays:        ageDays,
								Category:       rule.Category,
								RuleID:         rule.ID,
								RiskClass:      rule.RiskClass,
								Reason:         fmt.Sprintf("%s (stale for %.1fd, %s)", rule.Name, ageDays, format.FormatBytes(sz)),
								Evidence:       fmt.Sprintf("Last activity %.1fd ago (%s)", ageDays, lastActivity.Format("2006-01-02")),
								ProposedAction: act,
								CanDelete:      canDel,
								IsDir:          false,
								FileCount:      1,
								PackageName:    pkgName,
								UninstallArgs:  uninstallArgs,
								ModTime:        lastActivity,
								RootModTime:    lastActivity,
								DeviceID:       devId,
								InodeNum:       inoNum,
								HasIdentity:    hasId,
								IsGitIgnored:   checkPathIgnored(p),
								IsDevBinary:    rule.ID == "dev_binaries" || rule.Category == "Dev Binary" || rule.Category == "Development Binary" || IsExecutableBinary(p, info),
							}

							candMu.Lock()
							cand.ID = len(candidates) + 1
							candidates = append(candidates, cand)
							candMu.Unlock()

							atomic.AddInt64(&candidateCount, 1)
							atomic.AddInt64(&candidateBytes, sz)
						}
					}
				}
				return nil
			})
		}(targetPath)
	}

	walkWg.Wait()
	close(doneProgress)

	return candidates
}

func determineCandidateAction(rule *config.Rule, isDir bool, uninstallArgs []string, includeData bool, containsProtected bool) (string, bool) {
	if containsProtected {
		return "report-only", false
	}

	defaultDeleteAction := "delete_file"
	if isDir {
		defaultDeleteAction = "delete_dir"
	}

	switch rule.RiskClass {
	case config.RiskRegenerable:
		return defaultDeleteAction, true

	case config.RiskPackageManaged:
		return "report-only", false

	case config.RiskUserData:
		if includeData {
			return defaultDeleteAction, true
		}
		return "report-only", false

	case config.RiskUnknown:
		return "report-only", false

	default:
		return "report-only", false
	}
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
