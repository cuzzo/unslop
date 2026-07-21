package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed manifest.json
var defaultManifestData []byte

// Candidate represents a found stale file or directory
type Candidate struct {
	Path         string  `json:"path"`
	Size         int64   `json:"size"`
	AgeDays      float64 `json:"age_days"`
	Category     string  `json:"category"`
	IsDir        bool    `json:"is_dir"`
	FileCount    int64   `json:"file_count"`
	PackageName  string  `json:"package_name,omitempty"`
	UninstallCmd string  `json:"uninstall_cmd,omitempty"`
}

// Rule defines a single declarative scanning rule
type Rule struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Target           string   `json:"target"` // "dir", "file", "any"
	Patterns         []string `json:"patterns"`
	Category         string   `json:"category"`
	MinSizeMB        float64  `json:"min_size_mb,omitempty"`
	UninstallCmd     string   `json:"uninstall_cmd,omitempty"`
	CheckUnusedAtime bool     `json:"check_unused_atime,omitempty"`
}

// Manifest defines the top-level manifest file structure
type Manifest struct {
	DefaultDays      float64 `json:"default_days,omitempty"`
	DefaultMinSizeMB float64 `json:"default_min_size_mb,omitempty"`
	Rules            []Rule  `json:"rules"`
}

// RuleEngine manages O(1) and compiled rule lookups
type RuleEngine struct {
	Rules       []Rule
	ExactDirMap map[string]*Rule // "target" -> Rule
	ExtMap      map[string]*Rule // ".gguf" -> Rule
	GlobRules   []*Rule          // Wildcard & path rules
}

func NewRuleEngine(m Manifest) *RuleEngine {
	re := &RuleEngine{
		Rules:       m.Rules,
		ExactDirMap: make(map[string]*Rule),
		ExtMap:      make(map[string]*Rule),
	}

	for i := range m.Rules {
		r := &m.Rules[i]
		isGlob := false
		for _, pat := range r.Patterns {
			patLower := strings.ToLower(pat)
			if strings.HasPrefix(patLower, "*.") && !strings.Contains(patLower[2:], "/") && !strings.Contains(patLower[2:], "*") {
				re.ExtMap[patLower[1:]] = r
			} else if !strings.Contains(patLower, "*") && !strings.Contains(patLower, "/") {
				re.ExactDirMap[patLower] = r
			} else {
				isGlob = true
			}
		}
		if isGlob {
			re.GlobRules = append(re.GlobRules, r)
		}
	}
	return re
}

func (re *RuleEngine) MatchDir(name, path string) (*Rule, string, string) {
	nameLower := strings.ToLower(name)
	if rule, found := re.ExactDirMap[nameLower]; found {
		if rule.Target == "dir" || rule.Target == "any" {
			cmd := formatUninstallCmd(rule.UninstallCmd, name, path)
			return rule, name, cmd
		}
	}
	pathClean := filepath.ToSlash(path)
	for _, rule := range re.GlobRules {
		if rule.Target == "dir" || rule.Target == "any" {
			for _, pat := range rule.Patterns {
				if matchPattern(pathClean, pat) || matchPattern(name, pat) {
					cmd := formatUninstallCmd(rule.UninstallCmd, name, path)
					return rule, name, cmd
				}
			}
		}
	}
	return nil, "", ""
}

func (re *RuleEngine) MatchFile(name, path string, info os.FileInfo) (*Rule, string, string) {
	nameLower := strings.ToLower(name)
	ext := strings.ToLower(filepath.Ext(nameLower))
	pathClean := filepath.ToSlash(path)

	var matchedRule *Rule

	if ext != "" {
		if rule, found := re.ExtMap[ext]; found {
			if rule.Target == "file" || rule.Target == "any" {
				matchedRule = rule
			}
		}
	}

	if matchedRule == nil {
		for _, rule := range re.GlobRules {
			if rule.Target == "file" || rule.Target == "any" {
				for _, pat := range rule.Patterns {
					if matchPattern(pathClean, pat) || matchPattern(name, pat) {
						matchedRule = rule
						break
					}
				}
				if matchedRule != nil {
					break
				}
			}
		}
	}

	if matchedRule == nil {
		return nil, "", ""
	}

	if matchedRule.CheckUnusedAtime {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			atime := time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
			ctime := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
			diff := atime.Sub(ctime)
			if diff < 0 {
				diff = -diff
			}
			if diff > 24*time.Hour {
				return nil, "", "" // Executed after install
			}
		}
	}

	cmd := formatUninstallCmd(matchedRule.UninstallCmd, name, path)
	return matchedRule, name, cmd
}

func formatUninstallCmd(template, name, path string) string {
	if template == "" {
		return ""
	}
	res := strings.ReplaceAll(template, "{name}", name)
	res = strings.ReplaceAll(res, "{path}", path)
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) >= 2 {
		res = strings.ReplaceAll(res, "{candidate}", parts[len(parts)-2])
		res = strings.ReplaceAll(res, "{version}", parts[len(parts)-1])
	}
	return res
}

// Protected files/directories that MUST NEVER be matched or deleted
var protectedAgentPaths = []string{
	"config.toml", "settings.json", "credentials.json", ".credentials",
	"rules", "skills", "memories", "memory", "knowledge", "auth.json",
}

func isProtected(path string) bool {
	base := filepath.Base(path)
	baseLower := strings.ToLower(base)
	for _, p := range protectedAgentPaths {
		if baseLower == strings.ToLower(p) {
			return true
		}
	}
	return false
}

func getDiskSpace(path string) (uint64, uint64, uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, 0, 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free
	return total, used, free, nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatUintBytes(bytes uint64) string {
	return formatBytes(int64(bytes))
}

func matchPattern(name, pattern string) bool {
	nameLower := strings.ToLower(name)
	patLower := strings.ToLower(pattern)
	matched, err := filepath.Match(patLower, nameLower)
	if err == nil && matched {
		return true
	}
	return strings.Contains(nameLower, patLower)
}

func loadManifest(path string) Manifest {
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var m Manifest
			if err := json.Unmarshal(data, &m); err == nil && len(m.Rules) > 0 {
				return m
			}
		}
	}

	home, _ := os.UserHomeDir()

	// Check ~/.unslop.json in home directory
	if home != "" {
		dotPath := filepath.Join(home, ".unslop.json")
		if data, err := os.ReadFile(dotPath); err == nil {
			var m Manifest
			if err := json.Unmarshal(data, &m); err == nil && len(m.Rules) > 0 {
				return m
			}
		}
	}

	// Check XDG config directory (~/.config/unslop/manifest.json)
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" && home != "" {
		configDir = filepath.Join(home, ".config")
	}
	if configDir != "" {
		xdgPath := filepath.Join(configDir, "unslop", "manifest.json")
		if data, err := os.ReadFile(xdgPath); err == nil {
			var m Manifest
			if err := json.Unmarshal(data, &m); err == nil && len(m.Rules) > 0 {
				return m
			}
		}
	}

	// Fallback to embedded default manifest
	if len(defaultManifestData) > 0 {
		var m Manifest
		if err := json.Unmarshal(defaultManifestData, &m); err == nil && len(m.Rules) > 0 {
			if configDir != "" {
				userConfigPath := filepath.Join(configDir, "unslop", "manifest.json")
				_ = os.MkdirAll(filepath.Dir(userConfigPath), 0755)
				_ = os.WriteFile(userConfigPath, defaultManifestData, 0644)
			}
			return m
		}
	}

	return getDefaultManifest()
}

func getDefaultManifest() Manifest {
	return Manifest{
		DefaultDays:      3.0,
		DefaultMinSizeMB: 1.0,
		Rules: []Rule{
			{ID: "zig_cache", Name: "Zig Build Cache", Target: "dir", Patterns: []string{".zig-cache", "zig-cache", ".clear-cache", "clear-cache", ".clear-transpile-cache"}, Category: "Cache Dir"},
			{ID: "build_target", Name: "Project Build Targets", Target: "dir", Patterns: []string{"target", ".gradle", ".nuget", ".m2", ".npm", ".rubies", "node_modules/.cache", "kcov", "tmp*", "temp*", "_tmp*", "_temp*", "*.tmp", "*.temp"}, Category: "Cache Dir"},
			{ID: "llm_models", Name: "LLM Models & Weights", Target: "any", Patterns: []string{"*.gguf", "*.safetensors", "*.ckpt", "*.gexf", "*.llamafile", ".ollama/models", ".cache/huggingface/hub", ".lmstudio/models", ".cache/lm-studio", "jan/models", ".cache/llama.cpp"}, Category: "LLM Model"},
			{ID: "agent_sessions", Name: "AI Agent Sessions", Target: "any", Patterns: []string{"rollout-*.jsonl", ".codex/sessions", ".gemini/antigravity-cli/conversations"}, Category: "Agent Session"},
			{ID: "agent_cache", Name: "AI Agent Caches", Target: "dir", Patterns: []string{".codex/cache", ".codex/tmp", ".codex/.tmp", ".claude/cache", ".claude/paste-cache", ".gemini/antigravity-cli/cache", ".gemini/antigravity-cli/implicit", ".config/Cursor/Cache", ".config/Cursor/GPUCache", ".config/Cursor/User/workspaceStorage"}, Category: "Agent Cache"},
			{ID: "agent_logs", Name: "AI Agent Logs", Target: "any", Patterns: []string{".claude/debug", ".gemini/antigravity-cli/log", ".gemini/antigravity-cli/crashes", ".config/Cursor/logs"}, Category: "Agent Log"},
			{ID: "agent_history", Name: "AI Agent File History", Target: "any", Patterns: []string{".claude/file-history"}, Category: "Agent History"},
			{ID: "json_artifacts", Name: "Large JSON Dumps", Target: "file", Patterns: []string{"*.json", "*.jsonl"}, Category: "JSON Artifact", MinSizeMB: 5.0},
			{ID: "profile_data", Name: "Profile & Trace Dumps", Target: "file", Patterns: []string{"*.profile", "*.pprof", "perf.data*", "*.cpuprofile", "*.heapprofile", "*profile*.json", "*.trace", "trace*.err", "*.dmp", "bench.profile"}, Category: "Profile/Trace"},
			{ID: "temp_files", Name: "Temporary Files", Target: "file", Patterns: []string{"*.ll", "*.bc", "*.log", "*.err", "*.out"}, Category: "Temp File"},
			{ID: "cargo_pkg", Name: "Unused Cargo Package", Target: "file", Patterns: []string{"*/.cargo/bin/*"}, Category: "UNUSED (Cargo)", UninstallCmd: "cargo uninstall {name}", CheckUnusedAtime: true},
			{ID: "npm_pkg", Name: "Unused npm Package", Target: "file", Patterns: []string{"*/.nvm/versions/node/*/bin/*", "*/.npm-global/bin/*"}, Category: "UNUSED (npm)", UninstallCmd: "npm uninstall -g {name}", CheckUnusedAtime: true},
			{ID: "pipx_pkg", Name: "Unused pipx Package", Target: "file", Patterns: []string{"*/.local/pipx/venvs/*", "*/.local/bin/*"}, Category: "UNUSED (pipx)", UninstallCmd: "pipx uninstall {name}", CheckUnusedAtime: true},
			{ID: "swift_toolchain", Name: "Unused Swift Toolchain", Target: "dir", Patterns: []string{"*/.local/share/swiftly/toolchains/*"}, Category: "UNUSED (Swift)", UninstallCmd: "swiftly uninstall {name}"},
		},
	}
}

func applyOverrides(engine *RuleEngine, overrides []string) ([]string, []string) {
	var removed, added []string
	for _, raw := range overrides {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "-") {
			pat := strings.ToLower(item[1:])
			removed = append(removed, pat)
			filtered := []Rule{}
			for _, r := range engine.Rules {
				if strings.ToLower(r.ID) != pat && strings.ToLower(r.Category) != pat && !strings.Contains(strings.ToLower(r.Name), pat) {
					filtered = append(filtered, r)
				}
			}
			engine.Rules = filtered
		} else {
			pat := item
			if strings.HasPrefix(item, "+") {
				pat = item[1:]
			}
			added = append(added, pat)
			newRule := Rule{
				ID:       "custom_" + pat,
				Name:     "Custom Rule (" + pat + ")",
				Target:   "any",
				Patterns: []string{pat},
				Category: "Custom Rule",
			}
			engine.Rules = append(engine.Rules, newRule)
		}
	}
	*engine = *NewRuleEngine(Manifest{Rules: engine.Rules})
	return removed, added
}

func getDirStats(dirPath string, now time.Time) (int64, time.Time, int64) {
	var totalSize int64
	var maxMtime time.Time
	var fileCount int64

	filepath.WalkDir(dirPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			totalSize += info.Size()
			fileCount++
		}
		if info.ModTime().After(maxMtime) {
			maxMtime = info.ModTime()
		}
		return nil
	})

	if maxMtime.IsZero() {
		if fi, err := os.Lstat(dirPath); err == nil {
			maxMtime = fi.ModTime()
		} else {
			maxMtime = now
		}
	}
	return totalSize, maxMtime, fileCount
}

func precountFiles(scanDirs []string) int64 {
	var totalFiles int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)

	fmt.Fprintf(os.Stderr, "Indexing files for exact progress...\r")

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
			atomic.AddInt64(&totalFiles, 1)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, e := range entries {
			subPath := filepath.Join(p, e.Name())
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				var cnt int64
				filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					name := d.Name()
					if isProtected(path) {
						if d.IsDir() {
							return filepath.SkipDir
						}
						return nil
					}
					if d.IsDir() && (name == ".git" || name == ".hg" || name == ".svn") {
						return filepath.SkipDir
					}
					if !d.IsDir() {
						cnt++
					}
					return nil
				})
				atomic.AddInt64(&totalFiles, cnt)
			}(subPath)
		}
	}
	wg.Wait()
	return atomic.LoadInt64(&totalFiles)
}

func renderProgressBar(pct float64, width int) string {
	completed := int((pct / 100.0) * float64(width))
	if completed > width {
		completed = width
	}
	if completed < 0 {
		completed = 0
	}
	return "[" + strings.Repeat("█", completed) + strings.Repeat("░", width-completed) + "]"
}

func scanParallel(scanDirs []string, engine *RuleEngine, minDays float64, minSizeBytes int64) []Candidate {
	totalFilesToScan := precountFiles(scanDirs)
	if totalFilesToScan == 0 {
		totalFilesToScan = 1
	}

	now := time.Now()
	startTime := now
	candidatesChan := make(chan Candidate, 10000)
	var scannedFiles int64
	var candidateCount int64
	var candidateBytes int64

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
		entries, err := os.ReadDir(p)
		if err != nil || len(entries) == 0 {
			topLevelPaths = append(topLevelPaths, p)
			continue
		}
		for _, e := range entries {
			topLevelPaths = append(topLevelPaths, filepath.Join(p, e.Name()))
		}
	}

	var walkWg sync.WaitGroup

	doneProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-doneProgress:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				sFiles := atomic.LoadInt64(&scannedFiles)
				pct := (float64(sFiles) / float64(totalFilesToScan)) * 100.0
				if pct > 100.0 {
					pct = 100.0
				}
				bar := renderProgressBar(pct, 20)
				cBytes := atomic.LoadInt64(&candidateBytes)
				cCount := atomic.LoadInt64(&candidateCount)

				elapsedSec := time.Since(startTime).Seconds()
				filesPerSec := 0.0
				if elapsedSec > 0 {
					filesPerSec = float64(sFiles) / elapsedSec
				}

				fmt.Fprintf(os.Stderr, "\r\033[KScanning %s %5.1f%% | %s / %s files (%.0f/s) | Candidates: %d (%s)",
					bar, pct, formatNumber(sFiles), formatNumber(totalFilesToScan), filesPerSec, cCount, formatBytes(cBytes))
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

			filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				name := d.Name()

				if isProtected(p) {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if d.IsDir() && (name == ".git" || name == ".hg" || name == ".svn") {
					return filepath.SkipDir
				}

				if d.IsDir() && p != r {
					if rule, pkgName, uninstallCmd := engine.MatchDir(name, p); rule != nil {
						sz, maxMt, fCount := getDirStats(p, now)
						atomic.AddInt64(&scannedFiles, fCount)
						ageDays := now.Sub(maxMt).Hours() / 24.0

						reqMinSize := minSizeBytes
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}

						if ageDays >= minDays && sz >= reqMinSize {
							candidatesChan <- Candidate{
								Path:         p,
								Size:         sz,
								AgeDays:      ageDays,
								Category:     rule.Category,
								IsDir:        true,
								FileCount:    fCount,
								PackageName:  pkgName,
								UninstallCmd: uninstallCmd,
							}
							atomic.AddInt64(&candidateCount, 1)
							atomic.AddInt64(&candidateBytes, sz)
						}
						return filepath.SkipDir
					}
					if isTmp && filepath.Dir(p) == "/tmp" {
						sz, maxMt, fCount := getDirStats(p, now)
						atomic.AddInt64(&scannedFiles, fCount)
						ageDays := now.Sub(maxMt).Hours() / 24.0
						if ageDays >= minDays && sz >= minSizeBytes {
							candidatesChan <- Candidate{
								Path:      p,
								Size:      sz,
								AgeDays:   ageDays,
								Category:  "Tmp Dir",
								IsDir:     true,
								FileCount: fCount,
							}
							atomic.AddInt64(&candidateCount, 1)
							atomic.AddInt64(&candidateBytes, sz)
						}
						return filepath.SkipDir
					}
				}

				if !d.IsDir() {
					atomic.AddInt64(&scannedFiles, 1)
					info, err := d.Info()
					if err != nil {
						return nil
					}
					ageDays := now.Sub(info.ModTime()).Hours() / 24.0
					sz := info.Size()

					rule, pkgName, uninstallCmd := engine.MatchFile(name, p, info)
					cat := ""
					reqMinSize := minSizeBytes

					if rule != nil {
						cat = rule.Category
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}
					} else if isTmp && filepath.Dir(p) == "/tmp" {
						cat = "Tmp File"
					}

					if cat != "" && ageDays >= minDays && sz >= reqMinSize {
						candidatesChan <- Candidate{
							Path:         p,
							Size:         sz,
							AgeDays:      ageDays,
							Category:     cat,
							IsDir:        false,
							FileCount:    1,
							PackageName:  pkgName,
							UninstallCmd: uninstallCmd,
						}
						atomic.AddInt64(&candidateCount, 1)
						atomic.AddInt64(&candidateBytes, sz)
					}
				}
				return nil
			})
		}(targetPath)
	}

	walkWg.Wait()
	close(doneProgress)
	time.Sleep(50 * time.Millisecond)

	close(candidatesChan)

	var result []Candidate
	for c := range candidatesChan {
		result = append(result, c)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Size > result[j].Size
	})
	return result
}

func formatNumber(n int64) string {
	in := fmt.Sprintf("%d", n)
	out := ""
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}

func findFzf() string {
	if path, err := exec.LookPath("fzf"); err == nil {
		return path
	}
	home, _ := os.UserHomeDir()
	alt := filepath.Join(home, ".local", "bin", "fzf")
	if _, err := os.Stat(alt); err == nil {
		return alt
	}
	return ""
}

func runFzfInteractive(candidates []Candidate, fzfBin string, diskTotal, diskUsed, diskFree uint64) []Candidate {
	if len(candidates) == 0 {
		fmt.Println("No stale candidates found matching criteria.")
		return nil
	}

	var candidatesTotalBytes int64
	var lines []string
	for _, c := range candidates {
		candidatesTotalBytes += c.Size
		line := fmt.Sprintf("%-10s | %5.1fd | %-14s | %s",
			formatBytes(c.Size), c.AgeDays, c.Category, c.Path)
		lines = append(lines, line)
	}

	previewCmd := `ITEM=$(echo "{}" | cut -d'|' -f4 | sed 's/^[ \t]*//'); if [ -d "$ITEM" ]; then echo "DIR:  $ITEM"; echo "INFO: $(du -sh "$ITEM" 2>/dev/null | cut -f1) total space | $(find "$ITEM" -maxdepth 2 2>/dev/null | wc -l) files/subdirs"; echo "HEAD: $(ls -1 "$ITEM" 2>/dev/null | head -n 6 | tr "\n" " ")"; elif [ -f "$ITEM" ]; then echo "FILE: $ITEM"; echo "INFO: $(du -h "$ITEM" 2>/dev/null | cut -f1) | $(file -b "$ITEM" 2>/dev/null | head -c 80)"; echo "HEAD: $(head -n 2 "$ITEM" 2>/dev/null | tr "\n" " ")"; else echo "$ITEM"; fi 2>/dev/null`

	headerStr := fmt.Sprintf(
		"DISK: %s used / %s avail | CANDIDATES: %s (%s items)\nKEYS: [TAB/SPACE] Select | [CTRL-A] Select All | [ENTER] Confirm Staging",
		formatUintBytes(diskUsed), formatUintBytes(diskFree), formatBytes(candidatesTotalBytes), formatNumber(int64(len(candidates))),
	)

	cmd := exec.Command(fzfBin,
		"-m",
		"--ansi",
		"--bind=space:toggle+down",
		"--header="+headerStr,
		"--prompt=unslop> ",
		"--preview="+previewCmd,
		"--preview-window=bottom:4:wrap:border-top",
		"--height=100%",
		"--layout=reverse",
		"--border",
	)

	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil
	}

	go func() {
		defer stdin.Close()
		for _, l := range lines {
			fmt.Fprintln(stdin, l)
		}
	}()

	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		return nil
	}

	selectedLines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var selected []Candidate
	for _, line := range selectedLines {
		parts := strings.Split(line, " | ")
		if len(parts) >= 4 {
			p := strings.TrimSpace(parts[3])
			for _, c := range candidates {
				if c.Path == p {
					selected = append(selected, c)
					break
				}
			}
		}
	}
	return selected
}

func getDefaultScanDirs() []string {
	dirs := []string{"~", "/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/private/var/tmp"}
	for _, envVar := range []string{"TMPDIR", "TEMP", "TMP"} {
		if val := os.Getenv(envVar); val != "" {
			dirs = append(dirs, val)
		}
	}
	var res []string
	seen := make(map[string]bool)
	for _, d := range dirs {
		p := d
		if strings.HasPrefix(d, "~") {
			home, _ := os.UserHomeDir()
			p = filepath.Join(home, d[1:])
		}
		p = filepath.Clean(p)
		if !seen[p] {
			if _, err := os.Stat(p); err == nil {
				seen[p] = true
				res = append(res, d)
			}
		}
	}
	return res
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "unslop - High-performance interactive developer cache & stale artifact cleaner\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  unslop [options] [-remove-rule ...] [+custom-pattern ...]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nManifest Overrides (positional arguments):\n")
		fmt.Fprintf(os.Stderr, "  -category      Exclude a category or rule ID (e.g. -json_artifacts, -LLM)\n")
		fmt.Fprintf(os.Stderr, "  +pattern       Add a custom glob pattern to scan (e.g. +*.log, +tmp-*)\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  unslop -days 7 -min-size-mb 10\n")
		fmt.Fprintf(os.Stderr, "  unslop -path ~/.cache -path /tmp -dry-run\n")
		fmt.Fprintf(os.Stderr, "  unslop -json_artifacts +*.bak\n")
	}

	daysFlag := flag.Float64("days", 3.0, "Minimum age in days")
	minSizeFlag := flag.Float64("min-size-mb", 1.0, "Minimum size in MB")
	manifestFlag := flag.String("manifest", "", "Custom manifest JSON path")
	dryRunFlag := flag.Bool("dry-run", false, "Preview without deleting")

	var paths multimodFlag
	flag.Var(&paths, "path", "Directory path to scan (can specify multiple)")

	flag.Parse()

	daysSet := false
	minSizeSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "days" {
			daysSet = true
		}
		if f.Name == "min-size-mb" {
			minSizeSet = true
		}
	})

	fzfBin := findFzf()
	if fzfBin == "" {
		fmt.Fprintln(os.Stderr, "Error: fzf binary not found.")
		os.Exit(1)
	}

	scanDirs := []string(paths)
	if len(scanDirs) == 0 {
		scanDirs = getDefaultScanDirs()
	}

	manifest := loadManifest(*manifestFlag)
	engine := NewRuleEngine(manifest)
	applyOverrides(engine, flag.Args())

	minDays := *daysFlag
	if !daysSet && manifest.DefaultDays > 0 {
		minDays = manifest.DefaultDays
	}

	minSizeMB := *minSizeFlag
	if !minSizeSet && manifest.DefaultMinSizeMB > 0 {
		minSizeMB = manifest.DefaultMinSizeMB
	}

	minSizeBytes := int64(minSizeMB * 1024 * 1024)

	diskTotal, diskUsed, diskFree, _ := getDiskSpace("/")

	candidates := scanParallel(scanDirs, engine, minDays, minSizeBytes)

	selected := runFzfInteractive(candidates, fzfBin, diskTotal, diskUsed, diskFree)
	confirmAndDelete(selected, *dryRunFlag, diskUsed, diskFree)
}

type multimodFlag []string

func (m *multimodFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multimodFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func confirmAndDelete(selected []Candidate, dryRun bool, diskUsed, diskFree uint64) {
	if len(selected) == 0 {
		fmt.Println("No items selected. Exiting.")
		return
	}

	var total int64
	for _, c := range selected {
		total += c.Size
	}

	newDiskUsed := int64(diskUsed) - total
	if newDiskUsed < 0 {
		newDiskUsed = 0
	}

	fmt.Printf("\n============================================================\n")
	fmt.Printf(" STAGED FOR DELETION: %d items (%s)\n", len(selected), formatBytes(total))
	fmt.Printf(" DISK SAVINGS: %s used -> %s used (Will free %s)\n",
		formatUintBytes(diskUsed), formatBytes(newDiskUsed), formatBytes(total))
	fmt.Printf("============================================================\n")
	for _, c := range selected {
		kind := "FILE"
		if c.IsDir {
			kind = "DIR "
		}
		fmt.Printf(" [%s: %-13s] %10s | %4.1fd old | %s\n", kind, c.Category, formatBytes(c.Size), c.AgeDays, c.Path)
	}
	fmt.Printf("============================================================\n")

	if dryRun {
		fmt.Println("\n[DRY RUN] No files deleted.")
		return
	}

	fmt.Printf("\nAre you sure you want to permanently delete these %d items? (y/N): ", len(selected))
	reader := bufio.NewReader(os.Stdin)
	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) == "y" {
		fmt.Println("\nDeleting/Uninstalling items...")
		var freed int64
		for _, c := range selected {
			if c.UninstallCmd != "" {
				fmt.Printf(" [UNINSTALLING: %s] Running '%s'...\n", c.Category, c.UninstallCmd)
				cmd := exec.Command("sh", "-c", c.UninstallCmd)
				out, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Printf(" [ERROR] Native uninstall command '%s' failed: %v\n%s\n", c.UninstallCmd, err, strings.TrimSpace(string(out)))
					fmt.Printf(" Fallback: Remove binary file '%s' directly? (y/N): ", c.Path)
					ansFallback, _ := reader.ReadString('\n')
					if strings.ToLower(strings.TrimSpace(ansFallback)) == "y" {
						if errDel := os.Remove(c.Path); errDel == nil {
							freed += c.Size
							fmt.Printf(" [DELETED BINARY] %s\n", c.Path)
						} else {
							fmt.Printf(" [ERROR] Failed to remove binary file: %v\n", errDel)
						}
					}
				} else {
					freed += c.Size
					fmt.Printf(" [UNINSTALLED SUCCESS] %s via '%s'\n", c.Path, c.UninstallCmd)
				}
			} else {
				var err error
				if c.IsDir {
					err = os.RemoveAll(c.Path)
				} else {
					err = os.Remove(c.Path)
				}
				if err != nil {
					fmt.Printf(" [ERROR] Failed to delete %s: %v\n", c.Path, err)
				} else {
					freed += c.Size
					fmt.Printf(" [DELETED] %s\n", c.Path)
				}
			}
		}
		fmt.Printf("\nSuccessfully freed %s of disk space!\n", formatBytes(freed))
	} else {
		fmt.Println("\nOperation cancelled. No files were deleted.")
	}
}
