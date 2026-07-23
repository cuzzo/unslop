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

type GitAnalyzer struct{}

func NewGitAnalyzer() *GitAnalyzer {
	return &GitAnalyzer{}
}

func (g *GitAnalyzer) Kind() VCSKind {
	return VCSGit
}

func (g *GitAnalyzer) Detect(repoPath string) bool {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

type fileHistoryStats struct {
	path                  string
	addedInCommit         bool
	deletedInCommit       bool
	currentlyExists       bool
	commitCount           int
	maxSizeBytes          int64
	wasIgnoredAfterDelete bool
}

func (g *GitAnalyzer) AnalyzeHistory(repoPath string, opts ScanOptions) ([]HistoryCandidate, error) {
	if !g.Detect(repoPath) {
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
	ignoredPatterns := make(map[string]bool)
	fileStatsMap := make(map[string]*fileHistoryStats)
	depDirStatsMap := make(map[string]*fileHistoryStats)

	scanner := bufio.NewScanner(stdoutPipe)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var currentCommit string
	var processedCommits int64
	lastProgressTime := time.Now()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "COMMIT:") {
			currentCommit = strings.TrimPrefix(line, "COMMIT:")
			_ = currentCommit
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

		// Check if this file change is in a dependency directory (e.g., node_modules/, target/, vendor/)
		depRoot := ExtractDependencyRoot(cleanPath)
		if depRoot != "" {
			stat, ok := depDirStatsMap[depRoot]
			if !ok {
				stat = &fileHistoryStats{path: depRoot, addedInCommit: true}
				depDirStatsMap[depRoot] = stat
			}
			stat.commitCount++
			if strings.HasPrefix(status, "D") {
				stat.deletedInCommit = true
			}
			continue
		}

		// Track .gitignore / .hgignore updates
		if filepath.Base(cleanPath) == ".gitignore" || filepath.Base(cleanPath) == ".hgignore" {
			// Mark ignore pattern tracking flag
			ignoredPatterns[cleanPath] = true
		}

		stat, ok := fileStatsMap[cleanPath]
		if !ok {
			stat = &fileHistoryStats{path: cleanPath}
			fileStatsMap[cleanPath] = stat
		}
		stat.commitCount++

		if strings.HasPrefix(status, "A") {
			stat.addedInCommit = true
		} else if strings.HasPrefix(status, "D") {
			stat.deletedInCommit = true
		}
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
			depRoot := ExtractDependencyRoot(existingPath)
			if depRoot != "" {
				if stat, ok := depDirStatsMap[depRoot]; ok {
					stat.currentlyExists = true
				}
			}
		}
	}

	// 4. Batch query object sizes for tracked files/blobs using git cat-file & ls-tree/ls-files.
	g.populateFileSizes(repoPath, fileStatsMap)
	g.populateDepDirSizes(repoPath, depDirStatsMap)

	// 5. Detect deleted-then-ignored files by checking if gitignore rules were added.
	hasGitignoreUpdates := len(ignoredPatterns) > 0
	for _, stat := range fileStatsMap {
		if stat.deletedInCommit && !stat.currentlyExists && hasGitignoreUpdates {
			stat.wasIgnoredAfterDelete = true
		}
	}

	minSizeBytes := int64(opts.MinSizeMB * 1024 * 1024)
	var candidates []HistoryCandidate
	candidateID := 1

	// Aggregate dependency directories first
	for depRoot, stat := range depDirStatsMap {
		if minSizeBytes > 0 && stat.maxSizeBytes < minSizeBytes && stat.maxSizeBytes > 0 {
			continue
		}
		statusStr := "deleted"
		if stat.currentlyExists {
			statusStr = "existing"
		}

		candidates = append(candidates, HistoryCandidate{
			ID:          candidateID,
			Path:        depRoot,
			Size:        stat.maxSizeBytes,
			Category:    "Dependency Dump",
			RiskClass:   "history-bloat",
			Status:      statusStr,
			IsDebug:     false,
			CommitCount: stat.commitCount,
			CanDelete:   true,
		})
		candidateID++
	}

	// Aggregate individual file candidates
	for path, stat := range fileStatsMap {
		// EXPLICIT SAFETY GUARD: Never recommend deleting source code files ending in common extensions
		if IsSourceCodeFile(path) {
			continue
		}

		isDebug := IsDebugBinary(path)
		isDep := IsDependencyDumpPath(path)
		isGarbage := IsGarbageDumpPath(path)
		isLargeBin := IsLargeBinaryExtension(path)

		// Filter out files that don't match any bloat criteria
		if !isDebug && !isDep && !isGarbage && !isLargeBin && !stat.deletedInCommit && !stat.wasIgnoredAfterDelete {
			continue
		}

		// Apply size filter unless it's a debug binary or deleted-then-ignored or garbage file
		if minSizeBytes > 0 && stat.maxSizeBytes < minSizeBytes && !isDebug && !stat.wasIgnoredAfterDelete && !isGarbage {
			continue
		}

		statusStr := "deleted"
		if stat.currentlyExists {
			statusStr = "existing"
		}

		cat, debugFlag, riskClass := ClassifyCandidate(path, stat.deletedInCommit, stat.wasIgnoredAfterDelete, stat.maxSizeBytes)

		candidates = append(candidates, HistoryCandidate{
			ID:          candidateID,
			Path:        path,
			Size:        stat.maxSizeBytes,
			Category:    cat,
			RiskClass:   riskClass,
			Status:      statusStr,
			IsDebug:     debugFlag || isDebug,
			CommitCount: stat.commitCount,
			CanDelete:   true,
		})
		candidateID++
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

func (g *GitAnalyzer) populateFileSizes(repoPath string, fileStatsMap map[string]*fileHistoryStats) {
	// For files that currently exist, use os.Stat for exact disk size
	for path, stat := range fileStatsMap {
		fullPath := filepath.Join(repoPath, filepath.FromSlash(path))
		if fi, err := os.Stat(fullPath); err == nil && !fi.IsDir() {
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

func (g *GitAnalyzer) populateDepDirSizes(repoPath string, depDirStatsMap map[string]*fileHistoryStats) {
	// Calculate size of dependency directories from git objects or filesystem
	for depRoot, stat := range depDirStatsMap {
		fullPath := filepath.Join(repoPath, filepath.FromSlash(depRoot))
		var totalSize int64
		_ = filepath.Walk(fullPath, func(_ string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				totalSize += info.Size()
			}
			return nil
		})
		if totalSize > 0 {
			stat.maxSizeBytes = totalSize
		} else {
			// Estimate default nominal size if deleted
			stat.maxSizeBytes = 10 * 1024 * 1024
		}
	}
}
