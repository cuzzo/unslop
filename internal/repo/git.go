package repo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yahn/unslop/internal/ui"
)

func Detect(repoPath string) bool {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

type fileHistoryStats struct {
	deletedInCommit bool
	currentlyExists bool
	commitCount     int
	maxSizeBytes    int64
}

func AnalyzeHistory(repoPath string, opts ScanOptions) ([]HistoryCandidate, error) {
	if !Detect(repoPath) {
		return nil, fmt.Errorf("directory '%s' is not a valid Git repository", repoPath)
	}

	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Calculate total commits for accurate loading bar denominator
	var totalCommits int64
	countCmd := exec.Command("git", "-C", repoPath, "rev-list", "--count", "--all")
	if countOut, err := countCmd.Output(); err == nil {
		totalCommits, _ = strconv.ParseInt(strings.TrimSpace(string(countOut)), 10, 64)
	}

	// 1. Run git log --all --name-status to extract commit changes and file lifecycles in real-time stream.
	logCmd := exec.Command("git", "-C", repoPath, "log", "--all", "--name-status", "--pretty=format:COMMIT:%H")
	stdoutPipe, err := logCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe for git log: %w", err)
	}

	if err := logCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start git log process: %w", err)
	}
	defer func() {
		_ = logCmd.Wait()
	}()

	// 2. Track ignore rules added over time.
	hasGitignoreUpdates := false
	fileStatsMap := make(map[string]*fileHistoryStats)

	scanner := bufio.NewScanner(stdoutPipe)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var processedCommits int64
	lastProgressTime := time.Now()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "COMMIT:") {
			processedCommits++

			if stderr != nil && time.Since(lastProgressTime) >= 30*time.Millisecond {
				lastProgressTime = time.Now()
				if totalCommits > 0 {
					pct := (float64(processedCommits) / float64(totalCommits)) * 100.0
					if pct > 100.0 {
						pct = 100.0
					}
					bar := ui.RenderProgressBar(pct, 20)
					fmt.Fprintf(stderr, "\r\033[KProcessing Git history %s %5.1f%% (%d/%d commits)", bar, pct, processedCommits, totalCommits)
				} else {
					fmt.Fprintf(stderr, "\r\033[KProcessing Git history... %d commits processed", processedCommits)
				}
			}
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		status := parts[0]
		filePath := parts[len(parts)-1]
		cleanPath := filepath.ToSlash(filePath)

		if depRoot := ExtractDependencyRoot(cleanPath); depRoot != "" {
			cleanPath = depRoot
		} else if filepath.Base(cleanPath) == ".gitignore" || filepath.Base(cleanPath) == ".hgignore" {
			hasGitignoreUpdates = true
		}
		stat := fileStatsMap[cleanPath]
		if stat == nil {
			stat = &fileHistoryStats{}
			fileStatsMap[cleanPath] = stat
		}
		stat.commitCount++
		stat.deletedInCommit = stat.deletedInCommit || strings.HasPrefix(status, "D")
	}

	if stderr != nil && totalCommits > 0 {
		bar := ui.RenderProgressBar(100.0, 20)
		fmt.Fprintf(stderr, "\r\033[KProcessing Git history %s 100.0%% (%d/%d commits)\n", bar, totalCommits, totalCommits)
	}

	// 3. Inspect HEAD files to set currentlyExists flag.
	lsCmd := exec.Command("git", "-C", repoPath, "ls-files")
	lsOut, err := lsCmd.Output()
	if err == nil {
		lsScanner := bufio.NewScanner(bytes.NewReader(lsOut))
		for lsScanner.Scan() {
			existingPath := filepath.ToSlash(strings.TrimSpace(lsScanner.Text()))
			if stat, ok := fileStatsMap[existingPath]; ok {
				stat.currentlyExists = true
			}
			if stat := fileStatsMap[ExtractDependencyRoot(existingPath)]; stat != nil {
				stat.currentlyExists = true
			}
		}
	}

	populateFileSizes(repoPath, fileStatsMap)
	minSizeBytes := int64(opts.MinSizeMB * 1024 * 1024)
	var candidates []HistoryCandidate
	for path, stat := range fileStatsMap {
		isDependency := strings.HasSuffix(path, "/")
		if !isDependency && IsSourceCodeFile(path) {
			continue
		}
		ignoredAfterDelete := stat.deletedInCommit && !stat.currentlyExists && hasGitignoreUpdates
		category, isDebug, riskClass := ClassifyCandidate(path, stat.deletedInCommit, ignoredAfterDelete)
		if isDependency {
			if minSizeBytes > 0 && stat.maxSizeBytes < minSizeBytes && stat.maxSizeBytes > 0 {
				continue
			}
			category, isDebug = "Dependency Dump", false
		} else {
			isGarbage := IsGarbageDumpPath(path)
			if !isDebug && !isGarbage && !IsLargeBinaryExtension(path) && !stat.deletedInCommit {
				continue
			}
			if minSizeBytes > 0 && stat.maxSizeBytes < minSizeBytes && !isDebug && !ignoredAfterDelete && !isGarbage {
				continue
			}
		}
		status := "deleted"
		if stat.currentlyExists {
			status = "existing"
		}
		candidates = append(candidates, HistoryCandidate{
			Path: path, Size: stat.maxSizeBytes, Category: category, RiskClass: riskClass,
			Status: status, IsDebug: isDebug, CommitCount: stat.commitCount, CanDelete: true,
		})
	}

	// Sort candidates by size descending (highest size at the top)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Size != candidates[j].Size {
			return candidates[i].Size > candidates[j].Size
		}
		return candidates[i].Path < candidates[j].Path
	})

	// Reassign IDs 1..N based on size descending order
	for i := range candidates {
		candidates[i].ID = i + 1
	}

	return candidates, nil
}

func populateFileSizes(repoPath string, fileStatsMap map[string]*fileHistoryStats) {
	// For files that currently exist, use os.Stat for exact disk size
	for path, stat := range fileStatsMap {
		fullPath := filepath.Join(repoPath, filepath.FromSlash(path))
		if strings.HasSuffix(path, "/") {
			_ = filepath.Walk(fullPath, func(_ string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					stat.maxSizeBytes += info.Size()
				}
				return nil
			})
			if stat.maxSizeBytes == 0 {
				stat.maxSizeBytes = 10 * 1024 * 1024
			}
		} else if fi, err := os.Stat(fullPath); err == nil && !fi.IsDir() {
			stat.maxSizeBytes = fi.Size()
		}
	}

	// For deleted blobs or unpopulated sizes, use git rev-list --objects & git cat-file --batch-check
	revCmd := exec.Command("git", "-C", repoPath, "rev-list", "--objects", "--all")
	revOut, err := revCmd.Output()
	if err != nil {
		return
	}

	catCmd := exec.Command("git", "-C", repoPath, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(rest)")
	catCmd.Stdin = bytes.NewReader(revOut)
	catOut, err := catCmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(catOut))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 4 && parts[1] == "blob" {
			size, _ := strconv.ParseInt(parts[2], 10, 64)
			relPath := filepath.ToSlash(parts[3])
			if stat, ok := fileStatsMap[relPath]; ok {
				if size > stat.maxSizeBytes {
					stat.maxSizeBytes = size
				}
			}
		}
	}
}
