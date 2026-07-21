package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed manifest.json
var defaultManifestData []byte

const Version = "0.2.0-alpha"

// Candidate represents a found stale file or directory
type Candidate struct {
	ID             int       `json:"id"`
	Path           string    `json:"path"`
	Size           int64     `json:"size"`
	AgeDays        float64   `json:"age_days"`
	Category       string    `json:"category"`
	RuleID         string    `json:"rule_id"`
	RiskClass      string    `json:"risk_class"` // "regenerable", "package-managed", "user-data", "unknown"
	Reason         string    `json:"reason"`
	Evidence       string    `json:"evidence"`
	ProposedAction string    `json:"proposed_action"` // "delete_dir", "delete_file", "uninstall_package"
	IsDir          bool      `json:"is_dir"`
	FileCount      int64     `json:"file_count"`
	PackageName    string    `json:"package_name,omitempty"`
	UninstallArgs  []string  `json:"uninstall_args,omitempty"`
	IsData         bool      `json:"is_data"`
	ModTime        time.Time `json:"mod_time"`
}

// Rule defines a single declarative scanning rule
type Rule struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Target           string   `json:"target"` // "dir", "file", "any"
	Patterns         []string `json:"patterns"`
	Category         string   `json:"category"`
	RiskClass        string   `json:"risk_class,omitempty"`
	MinSizeMB        float64  `json:"min_size_mb,omitempty"`
	UninstallArgs    []string `json:"uninstall_args,omitempty"`
	CheckUnusedAtime bool     `json:"check_unused_atime,omitempty"`
	IsData           bool     `json:"is_data"`
}

// Manifest defines the top-level manifest file structure
type Manifest struct {
	DefaultDays      float64 `json:"default_days,omitempty"`
	DefaultMinSizeMB float64 `json:"default_min_size_mb,omitempty"`
	Rules            []Rule  `json:"rules"`
}

// PlanReport defines the structured JSON output for dry-run/plan mode
type PlanReport struct {
	Version      string `json:"version"`
	ScannedAt    string `json:"scanned_at"`
	DiskUsage    struct {
		TotalBytes uint64 `json:"total_bytes"`
		UsedBytes  uint64 `json:"used_bytes"`
		FreeBytes  uint64 `json:"free_bytes"`
	} `json:"disk_usage"`
	TotalCandidates int         `json:"total_candidates"`
	TotalSizeBytes  int64       `json:"total_size_bytes"`
	Candidates      []Candidate `json:"candidates"`
}

// RuleEngine manages O(1) and compiled rule lookups
type RuleEngine struct {
	Rules       []Rule
	ExactDirMap map[string]*Rule // "target" -> Rule
	ExtMap      map[string]*Rule // ".gguf" -> Rule
	GlobRules   []*Rule          // Wildcard & path rules
}

// PackageInventory caches mapped package managers
type PackageInventory struct {
	CargoCrates map[string]string // binary -> crate name
	PipxVenvs   map[string]string // binary -> pipx venv name
}

func loadPackageInventory() *PackageInventory {
	inv := &PackageInventory{
		CargoCrates: make(map[string]string),
		PipxVenvs:   make(map[string]string),
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return inv
	}

	cratesToml := filepath.Join(home, ".cargo", ".crates.toml")
	if data, err := os.ReadFile(cratesToml); err == nil {
		lines := strings.Split(string(data), "\n")
		re := regexp.MustCompile(`^"([^"]+)\s+[^"]+"\s*=\s*\[(.*)\]`)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			matches := re.FindStringSubmatch(line)
			if len(matches) == 3 {
				crateName := strings.Fields(matches[1])[0]
				binListStr := matches[2]
				binRe := regexp.MustCompile(`"([^"]+)"`)
				binMatches := binRe.FindAllStringSubmatch(binListStr, -1)
				for _, bMatch := range binMatches {
					if len(bMatch) == 2 {
						binName := bMatch[1]
						inv.CargoCrates[binName] = crateName
					}
				}
			}
		}
	}

	pipxDir := filepath.Join(home, ".local", "pipx", "venvs")
	if entries, err := os.ReadDir(pipxDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				inv.PipxVenvs[e.Name()] = e.Name()
			}
		}
	}

	return inv
}

func NewRuleEngine(m Manifest) *RuleEngine {
	re := &RuleEngine{
		Rules:       m.Rules,
		ExactDirMap: make(map[string]*Rule),
		ExtMap:      make(map[string]*Rule),
	}

	for i := range m.Rules {
		r := &m.Rules[i]
		if r.RiskClass == "" {
			if r.IsData {
				r.RiskClass = "user-data"
			} else if strings.HasPrefix(r.Category, "UNUSED") {
				r.RiskClass = "package-managed"
			} else {
				r.RiskClass = "regenerable"
			}
		}
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

func (re *RuleEngine) MatchDir(name, path string, inv *PackageInventory) (*Rule, string, []string) {
	nameLower := strings.ToLower(name)
	if rule, found := re.ExactDirMap[nameLower]; found {
		if rule.Target == "dir" || rule.Target == "any" {
			args := formatUninstallArgs(rule.Category, name, path, inv)
			return rule, name, args
		}
	}
	pathClean := filepath.ToSlash(path)
	for _, rule := range re.GlobRules {
		if rule.Target == "dir" || rule.Target == "any" {
			for _, pat := range rule.Patterns {
				if matchPattern(pathClean, pat) || matchPattern(name, pat) {
					args := formatUninstallArgs(rule.Category, name, path, inv)
					return rule, name, args
				}
			}
		}
	}
	return nil, "", nil
}

func (re *RuleEngine) MatchFile(name, path string, info os.FileInfo, inv *PackageInventory) (*Rule, string, []string) {
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
		return nil, "", nil
	}

	if matchedRule.CheckUnusedAtime {
		atime, ctime, _, isPosix := getStatTimes(info)
		if isPosix {
			diff := atime.Sub(ctime)
			if diff < 0 {
				diff = -diff
			}
			if diff > 24*time.Hour {
				return nil, "", nil // Executed after install
			}
		}
	}

	args := formatUninstallArgs(matchedRule.Category, name, path, inv)
	return matchedRule, name, args
}

func formatUninstallArgs(category, name, path string, inv *PackageInventory) []string {
	pathClean := filepath.ToSlash(path)

	switch category {
	case "UNUSED (Cargo)":
		if crateName, ok := inv.CargoCrates[name]; ok {
			return []string{"cargo", "uninstall", crateName}
		}
		return nil

	case "UNUSED (npm)":
		if name == "node" || name == "npm" || name == "npx" || name == "corepack" || name == "pnpm" || name == "yarn" {
			return nil
		}
		return []string{"npm", "uninstall", "-g", name}

	case "UNUSED (pipx)":
		if strings.Contains(pathClean, "/.local/pipx/venvs/") {
			parts := strings.Split(pathClean, "/.local/pipx/venvs/")
			if len(parts) > 1 {
				vName := strings.Split(parts[1], "/")[0]
				return []string{"pipx", "uninstall", vName}
			}
		}
		if target, err := os.Readlink(path); err == nil {
			targetClean := filepath.ToSlash(target)
			if strings.Contains(targetClean, "/.local/pipx/venvs/") {
				parts := strings.Split(targetClean, "/.local/pipx/venvs/")
				if len(parts) > 1 {
					vName := strings.Split(parts[1], "/")[0]
					return []string{"pipx", "uninstall", vName}
				}
			}
		}
		return nil

	case "UNUSED (Swift)":
		if strings.Contains(pathClean, "/.local/share/swiftly/toolchains/") {
			parts := strings.Split(pathClean, "/.local/share/swiftly/toolchains/")
			if len(parts) > 1 {
				version := strings.Split(parts[1], "/")[0]
				if version != "" {
					return []string{"swiftly", "uninstall", version}
				}
			}
		}
		return nil

	case "UNUSED (SDKMAN)":
		if strings.Contains(pathClean, "/.sdkman/candidates/") {
			parts := strings.Split(pathClean, "/.sdkman/candidates/")
			if len(parts) > 1 {
				subParts := strings.Split(parts[1], "/")
				if len(subParts) >= 2 {
					candidate := subParts[0]
					version := subParts[1]
					if version != "current" {
						return []string{"sdk", "uninstall", candidate, version}
					}
				}
			}
		}
		return nil

	case "UNUSED (Dotnet)":
		return []string{"dotnet", "tool", "uninstall", "-g", name}

	case "UNUSED (Composer)":
		return []string{"composer", "global", "remove", name}

	case "UNUSED (ZVM)":
		return []string{"zvm", "remove", name}
	}

	return nil
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

func containsProtectedPath(targetPath string) bool {
	var foundProtected bool
	filepath.WalkDir(targetPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if isProtected(p) {
			foundProtected = true
			return filepath.SkipAll
		}
		return nil
	})
	return foundProtected
}

func getDiskSpace(path string) (uint64, uint64, uint64, error) {
	tot, used, free, err := getDiskSpaceSyscall(path)
	if err != nil {
		return 100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024, nil
	}
	return tot, used, free, nil
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

func loadManifest(path string) (Manifest, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Manifest{}, fmt.Errorf("failed to read manifest flag path '%s': %w", path, err)
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return Manifest{}, fmt.Errorf("failed to parse JSON manifest at '%s': %w", path, err)
		}
		return m, nil
	}

	home, _ := os.UserHomeDir()

	if home != "" {
		dotPath := filepath.Join(home, ".unslop.json")
		if data, err := os.ReadFile(dotPath); err == nil {
			var m Manifest
			if err := json.Unmarshal(data, &m); err == nil && len(m.Rules) > 0 {
				return m, nil
			}
		}
	}

	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" && home != "" {
		configDir = filepath.Join(home, ".config")
	}
	if configDir != "" {
		xdgPath := filepath.Join(configDir, "unslop", "manifest.json")
		if data, err := os.ReadFile(xdgPath); err == nil {
			var m Manifest
			if err := json.Unmarshal(data, &m); err == nil && len(m.Rules) > 0 {
				return m, nil
			}
		}
	}

	if len(defaultManifestData) > 0 {
		var m Manifest
		if err := json.Unmarshal(defaultManifestData, &m); err == nil && len(m.Rules) > 0 {
			if configDir != "" {
				userConfigPath := filepath.Join(configDir, "unslop", "manifest.json")
				_ = os.MkdirAll(filepath.Dir(userConfigPath), 0755)
				_ = os.WriteFile(userConfigPath, defaultManifestData, 0644)
			}
			return m, nil
		}
	}

	return getDefaultManifest(), nil
}

func calculateDynamicMinSizeMB(diskTotalBytes uint64) float64 {
	const minFloorMB = 0.1 // 100 KB
	const maxCapMB = 50.0   // 50 MB

	if diskTotalBytes == 0 {
		return 10.0
	}

	diskGB := float64(diskTotalBytes) / (1024.0 * 1024.0 * 1024.0)

	var minSizeMB float64
	if diskGB <= 50.0 {
		minSizeMB = 1.0
	} else if diskGB >= 1000.0 {
		minSizeMB = maxCapMB
	} else {
		ratio := math.Log10(diskGB/50.0) / math.Log10(2.0)
		minSizeMB = 1.0 + ratio*9.0
	}

	if minSizeMB < minFloorMB {
		minSizeMB = minFloorMB
	}
	if minSizeMB > maxCapMB {
		minSizeMB = maxCapMB
	}

	return minSizeMB
}

func getDefaultManifest() Manifest {
	return Manifest{
		DefaultDays: 7.0,
		Rules: []Rule{
			{ID: "zig_cache", Name: "Zig Build Cache", Target: "dir", Patterns: []string{".zig-cache", "zig-cache", ".clear-cache", "clear-cache", ".clear-transpile-cache"}, Category: "Cache Dir", RiskClass: "regenerable", IsData: false},
			{ID: "build_target", Name: "Project Build Targets", Target: "dir", Patterns: []string{"target", ".gradle", ".nuget", ".m2", ".npm", ".rubies", "node_modules/.cache", "kcov", "tmp*", "temp*", "_tmp*", "_temp*", "*.tmp", "*.temp"}, Category: "Cache Dir", RiskClass: "regenerable", IsData: false},
			{ID: "llm_models", Name: "LLM Models & Weights", Target: "any", Patterns: []string{"*.gguf", "*.safetensors", "*.ckpt", "*.gexf", "*.llamafile", ".ollama/models", ".cache/huggingface/hub", ".lmstudio/models", ".cache/lm-studio", "jan/models", ".cache/llama.cpp"}, Category: "LLM Model", RiskClass: "user-data", IsData: true},
			{ID: "agent_sessions", Name: "AI Agent Sessions", Target: "any", Patterns: []string{"rollout-*.jsonl", ".codex/sessions", ".gemini/antigravity-cli/conversations"}, Category: "Agent Session", RiskClass: "user-data", IsData: true},
			{ID: "agent_cache", Name: "AI Agent Caches", Target: "dir", Patterns: []string{".codex/cache", ".codex/tmp", ".codex/.tmp", ".claude/cache", ".claude/paste-cache", ".gemini/antigravity-cli/cache", ".gemini/antigravity-cli/implicit", ".config/Cursor/Cache", ".config/Cursor/GPUCache", ".config/Cursor/User/workspaceStorage"}, Category: "Agent Cache", RiskClass: "regenerable", IsData: false},
			{ID: "agent_logs", Name: "AI Agent Logs", Target: "any", Patterns: []string{".claude/debug", ".gemini/antigravity-cli/log", ".gemini/antigravity-cli/crashes", ".config/Cursor/logs"}, Category: "Agent Log", RiskClass: "user-data", IsData: true},
			{ID: "agent_history", Name: "AI Agent File History", Target: "any", Patterns: []string{".claude/file-history"}, Category: "Agent History", RiskClass: "user-data", IsData: true},
			{ID: "json_artifacts", Name: "Large JSON Dumps", Target: "file", Patterns: []string{"*.json", "*.jsonl"}, Category: "JSON Artifact", MinSizeMB: 5.0, RiskClass: "user-data", IsData: true},
			{ID: "profile_data", Name: "Profile & Trace Dumps", Target: "file", Patterns: []string{"*.profile", "*.pprof", "perf.data*", "*.cpuprofile", "*.heapprofile", "*profile*.json", "*.trace", "trace*.err", "*.dmp", "bench.profile"}, Category: "Profile/Trace", RiskClass: "user-data", IsData: true},
			{ID: "temp_files", Name: "Temporary Files", Target: "file", Patterns: []string{"*.ll", "*.bc", "*.log", "*.err", "*.out"}, Category: "Temp File", RiskClass: "regenerable", IsData: false},
			{ID: "cargo_pkg", Name: "Unused Cargo Package", Target: "file", Patterns: []string{"*/.cargo/bin/*"}, Category: "UNUSED (Cargo)", CheckUnusedAtime: true, RiskClass: "package-managed", IsData: false},
			{ID: "npm_pkg", Name: "Unused npm Package", Target: "file", Patterns: []string{"*/.nvm/versions/node/*/bin/*", "*/.npm-global/bin/*"}, Category: "UNUSED (npm)", CheckUnusedAtime: true, RiskClass: "package-managed", IsData: false},
			{ID: "pipx_pkg", Name: "Unused pipx Package", Target: "file", Patterns: []string{"*/.local/pipx/venvs/*", "*/.local/bin/*"}, Category: "UNUSED (pipx)", CheckUnusedAtime: true, RiskClass: "package-managed", IsData: false},
			{ID: "swift_toolchain", Name: "Unused Swift Toolchain", Target: "dir", Patterns: []string{"*/.local/share/swiftly/toolchains/*"}, Category: "UNUSED (Swift)", RiskClass: "package-managed", IsData: false},
			{ID: "sdkman_cand", Name: "Unused SDKMAN Candidate", Target: "dir", Patterns: []string{"*/.sdkman/candidates/*/*"}, Category: "UNUSED (SDKMAN)", RiskClass: "package-managed", IsData: false},
			{ID: "dotnet_pkg", Name: "Unused .NET Tool", Target: "file", Patterns: []string{"*/.dotnet/tools/*"}, Category: "UNUSED (Dotnet)", CheckUnusedAtime: true, RiskClass: "package-managed", IsData: false},
			{ID: "composer_pkg", Name: "Unused Composer Package", Target: "file", Patterns: []string{"*/.config/composer/vendor/bin/*", "*/.composer/vendor/bin/*"}, Category: "UNUSED (Composer)", CheckUnusedAtime: true, RiskClass: "package-managed", IsData: false},
			{ID: "zvm_toolchain", Name: "Unused Zig Toolchain", Target: "any", Patterns: []string{"*/.zvm/bin/*", "*/.zvm/zig/*"}, Category: "UNUSED (ZVM)", RiskClass: "package-managed", IsData: false},
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
				ID:        "custom_" + pat,
				Name:      "Custom Rule (" + pat + ")",
				Target:    "any",
				Patterns:  []string{pat},
				Category:  "Custom Rule",
				RiskClass: "unknown",
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

// Single-pass high performance traversal
func scanParallel(scanDirs []string, engine *RuleEngine, minDays float64, minSizeBytes int64, includeData bool) []Candidate {
	inv := loadPackageInventory()

	now := time.Now()
	startTime := now
	var scannedFiles int64
	var candidateCount int64
	var candidateBytes int64

	var candidates []Candidate
	var candMu sync.Mutex

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
	currentUID := os.Getuid()

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
				cBytes := atomic.LoadInt64(&candidateBytes)
				cCount := atomic.LoadInt64(&candidateCount)

				elapsedSec := time.Since(startTime).Seconds()
				filesPerSec := 0.0
				if elapsedSec > 0 {
					filesPerSec = float64(sFiles) / elapsedSec
				}

				fmt.Fprintf(os.Stderr, "\r\033[KScanning... %s files (%.0f/s) | Candidates: %d (%s)",
					formatNumber(sFiles), filesPerSec, cCount, formatBytes(cBytes))
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

				if isTmp {
					if info, err := d.Info(); err == nil {
						_, _, uid, isPosix := getStatTimes(info)
						if isPosix && uid != currentUID {
							if d.IsDir() {
								return filepath.SkipDir
							}
							return nil
						}
						mode := info.Mode()
						if mode&(os.ModeSocket|os.ModeNamedPipe|os.ModeDevice|os.ModeCharDevice) != 0 {
							return nil
						}
					}
					nameLower := strings.ToLower(name)
					if strings.HasSuffix(nameLower, ".sock") || strings.HasSuffix(nameLower, ".lock") || strings.HasSuffix(nameLower, ".pid") {
						return nil
					}
				}

				if d.IsDir() && p != r {
					if rule, pkgName, uninstallArgs := engine.MatchDir(name, p, inv); rule != nil {
						if rule.IsData && !includeData {
							return filepath.SkipDir
						}
						sz, maxMt, fCount := getDirStats(p, now)
						atomic.AddInt64(&scannedFiles, fCount)
						ageDays := now.Sub(maxMt).Hours() / 24.0

						reqMinSize := minSizeBytes
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}

						if ageDays >= minDays && sz >= reqMinSize {
							action := "delete_dir"
							if len(uninstallArgs) > 0 {
								action = "uninstall_package"
							}
							cand := Candidate{
								Path:           p,
								Size:           sz,
								AgeDays:        ageDays,
								Category:       rule.Category,
								RuleID:         rule.ID,
								RiskClass:      rule.RiskClass,
								Reason:         fmt.Sprintf("Stale build cache unused for %.1f days", ageDays),
								Evidence:       fmt.Sprintf("Last modified %.1f days ago, total size %s across %d files", ageDays, formatBytes(sz), fCount),
								ProposedAction: action,
								IsDir:          true,
								FileCount:      fCount,
								PackageName:    pkgName,
								UninstallArgs:  uninstallArgs,
								IsData:         rule.IsData,
								ModTime:        maxMt,
							}
							candMu.Lock()
							candidates = append(candidates, cand)
							candMu.Unlock()

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
					sz := info.Size()

					if sz < 100*1024 {
						return nil
					}

					ageDays := now.Sub(info.ModTime()).Hours() / 24.0

					rule, pkgName, uninstallArgs := engine.MatchFile(name, p, info, inv)
					cat := ""
					reqMinSize := minSizeBytes
					isDataRule := false
					riskClass := "unknown"
					ruleID := ""

					if rule != nil {
						if rule.IsData && !includeData {
							return nil
						}
						cat = rule.Category
						ruleID = rule.ID
						riskClass = rule.RiskClass
						isDataRule = rule.IsData
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}
					}

					if cat != "" && ageDays >= minDays && sz >= reqMinSize {
						action := "delete_file"
						if len(uninstallArgs) > 0 {
							action = "uninstall_package"
						}
						cand := Candidate{
							Path:           p,
							Size:           sz,
							AgeDays:        ageDays,
							Category:       cat,
							RuleID:         ruleID,
							RiskClass:      riskClass,
							Reason:         fmt.Sprintf("Stale file unused for %.1f days", ageDays),
							Evidence:       fmt.Sprintf("Last modified %.1f days ago, size %s", ageDays, formatBytes(sz)),
							ProposedAction: action,
							IsDir:          false,
							FileCount:      1,
							PackageName:    pkgName,
							UninstallArgs:  uninstallArgs,
							IsData:         isDataRule,
							ModTime:        info.ModTime(),
						}
						candMu.Lock()
						candidates = append(candidates, cand)
						candMu.Unlock()

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

	seenPath := make(map[string]bool)
	var deduped []Candidate
	for _, c := range candidates {
		if !seenPath[c.Path] {
			seenPath[c.Path] = true
			deduped = append(deduped, c)
		}
	}

	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].Size > deduped[j].Size
	})

	for i := range deduped {
		deduped[i].ID = i + 1
	}

	return deduped
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

	candidateMap := make(map[int]Candidate)
	var candidatesTotalBytes int64
	var lines []string
	for _, c := range candidates {
		candidateMap[c.ID] = c
		candidatesTotalBytes += c.Size
		dataBadge := ""
		if c.IsData {
			dataBadge = " [REVIEW DATA]"
		}
		line := fmt.Sprintf("[%04d] %-10s | %5.1fd | %-14s | %s%s",
			c.ID, formatBytes(c.Size), c.AgeDays, c.Category, c.Path, dataBadge)
		lines = append(lines, line)
	}

	// Redacted preview command to obscure credentials, keys, and tokens
	previewCmd := `LINE="{}"; ITEM=$(echo "$LINE" | sed 's/^\[[0-9]*\]\s*//' | cut -d'|' -f4 | sed 's/^[ \t]*//' | sed 's/ \[REVIEW DATA\]$//'); if [ -d "$ITEM" ]; then echo "DIR:  $ITEM"; echo "INFO: $(du -sh "$ITEM" 2>/dev/null | cut -f1) total space | $(find "$ITEM" -maxdepth 2 2>/dev/null | wc -l) files/subdirs"; echo "HEAD: $(ls -1 "$ITEM" 2>/dev/null | head -n 6 | tr "\n" " ")"; elif [ -f "$ITEM" ]; then echo "FILE: $ITEM"; echo "INFO: $(du -h "$ITEM" 2>/dev/null | cut -f1) | $(file -b "$ITEM" 2>/dev/null | head -c 80)"; echo "HEAD (Sanitized): $(head -n 4 "$ITEM" 2>/dev/null | sed -E 's/(sk-[a-zA-Z0-9_-]{10,})/REDACTED_API_KEY/g; s/(eyJ[a-zA-Z0-9_-]{10,})/REDACTED_JWT/g; s/(BEGIN [A-Z ]+ PRIVATE KEY)/REDACTED_PRIVATE_KEY/g' | tr "\n" " ")"; else echo "$ITEM"; fi 2>/dev/null`

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
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			idStr := line[1:strings.Index(line, "]")]
			if id, err := strconv.Atoi(idStr); err == nil {
				if c, found := candidateMap[id]; found {
					selected = append(selected, c)
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

var osExit = os.Exit

func main() {
	osExit(runMain(os.Args[1:], os.Stdout, os.Stderr, os.Stdin))
}

func runMain(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	flags := flag.NewFlagSet("unslop", flag.ContinueOnError)
	flags.SetOutput(stderr)

	daysFlag := flags.Float64("days", 7.0, "Minimum age in days")
	minSizeFlag := flags.Float64("min-size-mb", 0.0, "Minimum size in MB (default: dynamic disk-scaled)")
	manifestFlag := flags.String("manifest", "", "Custom manifest JSON path")
	dryRunFlag := flags.Bool("dry-run", false, "Preview without deleting")
	applyFlag := flags.Bool("apply", false, "Enable permanent deletion mode")
	jsonFlag := flags.Bool("json", false, "Output structured JSON plan report")
	planOutFlag := flags.String("plan-out", "", "Export JSON plan report to file path")
	includeDataFlag := flags.Bool("include-data", false, "Include review-only data (LLM weights, agent sessions, JSON dumps)")
	trashFlag := flags.Bool("trash", false, "Move to Trash instead of permanent deletion")
	versionFlag := flags.Bool("version", false, "Print version and exit")

	var paths multimodFlag
	flags.Var(&paths, "path", "Directory path to scan (can specify multiple)")

	flags.Usage = func() {
		fmt.Fprintf(stderr, "unslop %s - Conservative developer workstation hygiene planner\n\n", Version)
		fmt.Fprintf(stderr, "Usage:\n")
		fmt.Fprintf(stderr, "  unslop [options] [-remove-rule ...] [+custom-pattern ...]\n\n")
		fmt.Fprintf(stderr, "Options:\n")
		flags.PrintDefaults()
		fmt.Fprintf(stderr, "\nManifest Overrides (positional arguments):\n")
		fmt.Fprintf(stderr, "  -category      Exclude a category or rule ID (e.g. -json_artifacts, -LLM)\n")
		fmt.Fprintf(stderr, "  +pattern       Add a custom glob pattern to scan (e.g. +*.log, +tmp-*)\n")
		fmt.Fprintf(stderr, "\nExamples:\n")
		fmt.Fprintf(stderr, "  unslop -days 7 -min-size-mb 10\n")
		fmt.Fprintf(stderr, "  unslop -json -plan-out plan.json\n")
		fmt.Fprintf(stderr, "  unslop -include-data (Include LLM weights, agent sessions, and JSON dumps)\n")
		fmt.Fprintf(stderr, "  unslop -apply (Enable deletion mode; defaults to plan/report mode)\n")
	}

	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *versionFlag {
		fmt.Fprintf(stdout, "unslop version %s\n", Version)
		return 0
	}

	daysSet := false
	minSizeSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "days" {
			daysSet = true
		}
		if f.Name == "min-size-mb" {
			minSizeSet = true
		}
	})

	scanDirs := []string(paths)
	if len(scanDirs) == 0 {
		scanDirs = getDefaultScanDirs()
	}

	manifest, err := loadManifest(*manifestFlag)
	if err != nil {
		fmt.Fprintf(stderr, "[FATAL] %v\n", err)
		return 1
	}

	engine := NewRuleEngine(manifest)
	applyOverrides(engine, flags.Args())

	diskTotal, diskUsed, diskFree, _ := getDiskSpace("/")
	dynamicMinSizeMB := calculateDynamicMinSizeMB(diskTotal)

	minDays := *daysFlag
	if !daysSet && manifest.DefaultDays > 0 {
		minDays = manifest.DefaultDays
	}

	minSizeMB := *minSizeFlag
	if !minSizeSet {
		if manifest.DefaultMinSizeMB > 0 {
			minSizeMB = manifest.DefaultMinSizeMB
		} else {
			minSizeMB = dynamicMinSizeMB
		}
	}
	if minSizeMB <= 0 {
		minSizeMB = dynamicMinSizeMB
	}

	minSizeBytes := int64(minSizeMB * 1024 * 1024)

	candidates := scanParallel(scanDirs, engine, minDays, minSizeBytes, *includeDataFlag)

	var totalCandidatesSizeBytes int64
	for _, c := range candidates {
		totalCandidatesSizeBytes += c.Size
	}

	if *jsonFlag || *planOutFlag != "" {
		report := PlanReport{
			Version:   Version,
			ScannedAt: time.Now().UTC().Format(time.RFC3339),
			DiskUsage: struct {
				TotalBytes uint64 `json:"total_bytes"`
				UsedBytes  uint64 `json:"used_bytes"`
				FreeBytes  uint64 `json:"free_bytes"`
			}{
				TotalBytes: diskTotal,
				UsedBytes:  diskUsed,
				FreeBytes:  diskFree,
			},
			TotalCandidates: len(candidates),
			TotalSizeBytes:  totalCandidatesSizeBytes,
			Candidates:      candidates,
		}

		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Error marshaling JSON plan: %v\n", err)
			return 1
		}

		if *jsonFlag {
			fmt.Fprintln(stdout, string(jsonData))
		}
		if *planOutFlag != "" {
			if err := os.WriteFile(*planOutFlag, jsonData, 0644); err != nil {
				fmt.Fprintf(stderr, "Error writing plan report to '%s': %v\n", *planOutFlag, err)
				return 1
			}
			fmt.Fprintf(stderr, "JSON plan exported successfully to '%s'\n", *planOutFlag)
		}

		if !*applyFlag && !*dryRunFlag {
			return 0
		}
	}

	fzfBin := findFzf()
	if fzfBin == "" {
		fmt.Fprintf(stderr, "\n[PLAN REPORT] fzf runtime binary not found. Standard text summary output below:\n\n")
		for _, c := range candidates {
			fmt.Fprintf(stdout, " [%-14s | %-16s] %10s | %4.1fd | %s\n", c.RiskClass, c.Category, formatBytes(c.Size), c.AgeDays, c.Path)
		}
		fmt.Fprintf(stdout, "\nTotal candidates: %d (%s)\n", len(candidates), formatBytes(totalCandidatesSizeBytes))
		return 0
	}

	selected := runFzfInteractive(candidates, fzfBin, diskTotal, diskUsed, diskFree)

	isDryRun := *dryRunFlag || !*applyFlag
	confirmAndDeleteWithIO(selected, isDryRun, *trashFlag, diskUsed, diskFree, stdout, stdin)
	return 0
}

type multimodFlag []string

func (m *multimodFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multimodFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func moveToTrash(path string) error {
	if gioBin, err := exec.LookPath("gio"); err == nil {
		cmd := exec.Command(gioBin, "trash", path)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	if trashBin, err := exec.LookPath("trash"); err == nil {
		cmd := exec.Command(trashBin, path)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	trashFilesDir := filepath.Join(home, ".local", "share", "Trash", "files")
	if err := os.MkdirAll(trashFilesDir, 0755); err != nil {
		return err
	}
	dest := filepath.Join(trashFilesDir, filepath.Base(path))
	return os.Rename(path, dest)
}

func confirmAndDelete(selected []Candidate, dryRun bool, useTrash bool, diskUsed, diskFree uint64) {
	confirmAndDeleteWithIO(selected, dryRun, useTrash, diskUsed, diskFree, os.Stdout, os.Stdin)
}

func confirmAndDeleteWithIO(selected []Candidate, dryRun bool, useTrash bool, diskUsed, diskFree uint64, stdout io.Writer, stdin io.Reader) {
	if len(selected) == 0 {
		fmt.Fprintln(stdout, "No items selected. Exiting.")
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

	fmt.Fprintf(stdout, "\n============================================================\n")
	fmt.Fprintf(stdout, " STAGED FOR DELETION: %d items (%s)\n", len(selected), formatBytes(total))
	fmt.Fprintf(stdout, " DISK SAVINGS: %s used -> %s used (Will free %s)\n",
		formatUintBytes(diskUsed), formatBytes(newDiskUsed), formatBytes(total))
	fmt.Fprintf(stdout, "============================================================\n")
	for _, c := range selected {
		kind := "FILE"
		if c.IsDir {
			kind = "DIR "
		}
		dataTag := ""
		if c.IsData {
			dataTag = " [REVIEW DATA]"
		}
		fmt.Fprintf(stdout, " [%s: %-13s | RISK: %-16s] %10s | %4.1fd old | %s%s\n", kind, c.Category, c.RiskClass, formatBytes(c.Size), c.AgeDays, c.Path, dataTag)
	}
	fmt.Fprintf(stdout, "============================================================\n")

	if dryRun {
		fmt.Fprintln(stdout, "\n[READ-ONLY PLAN MODE] No files were deleted. Pass '-apply' flag to execute deletion.")
		return
	}

	fmt.Fprintf(stdout, "\nAre you sure you want to permanently delete these %d items? (y/N): ", len(selected))
	reader := bufio.NewReader(stdin)
	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) == "y" {
		fmt.Fprintln(stdout, "\nDeleting/Uninstalling items...")
		var freed int64
		for _, c := range selected {
			info, err := os.Lstat(c.Path)
			if err != nil {
				fmt.Fprintf(stdout, " [SKIP] %s no longer exists on disk.\n", c.Path)
				continue
			}

			if info.IsDir() != c.IsDir {
				fmt.Fprintf(stdout, " [ABORT] File type changed for %s! Skipping.\n", c.Path)
				continue
			}

			if c.IsDir && containsProtectedPath(c.Path) {
				fmt.Fprintf(stdout, " [PROTECTED SAFEGUARD] %s contains protected credential/config files inside. Refusing deletion!\n", c.Path)
				continue
			}

			if len(c.UninstallArgs) > 0 {
				execStr := strings.Join(c.UninstallArgs, " ")
				fmt.Fprintf(stdout, " [UNINSTALLING: %s] Running '%s'...\n", c.Category, execStr)
				cmd := exec.Command(c.UninstallArgs[0], c.UninstallArgs[1:]...)
				out, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Fprintf(stdout, " [ERROR] Native uninstall failed: %v\n%s\n", err, strings.TrimSpace(string(out)))
					fmt.Fprintf(stdout, " Fallback: Remove '%s' directly? (y/N): ", c.Path)
					ansFallback, _ := reader.ReadString('\n')
					if strings.ToLower(strings.TrimSpace(ansFallback)) == "y" {
						if useTrash {
							if errTrash := moveToTrash(c.Path); errTrash == nil {
								freed += c.Size
								fmt.Fprintf(stdout, " [TRASHED] %s\n", c.Path)
							} else {
								fmt.Fprintf(stdout, " [ERROR] Failed to trash: %v\n", errTrash)
							}
						} else {
							var errDel error
							if c.IsDir {
								errDel = os.RemoveAll(c.Path)
							} else {
								errDel = os.Remove(c.Path)
							}
							if errDel == nil {
								freed += c.Size
								fmt.Fprintf(stdout, " [DELETED BINARY] %s\n", c.Path)
							} else {
								fmt.Fprintf(stdout, " [ERROR] Failed to remove binary: %v\n", errDel)
							}
						}
					}
				} else {
					freed += c.Size
					fmt.Fprintf(stdout, " [UNINSTALLED SUCCESS] %s via '%s'\n", c.Path, execStr)
				}
			} else {
				if useTrash {
					if errTrash := moveToTrash(c.Path); errTrash == nil {
						freed += c.Size
						fmt.Fprintf(stdout, " [TRASHED] %s\n", c.Path)
					} else {
						fmt.Fprintf(stdout, " [ERROR] Failed to trash %s: %v\n", c.Path, errTrash)
					}
				} else {
					var errDel error
					if c.IsDir {
						errDel = os.RemoveAll(c.Path)
					} else {
						errDel = os.Remove(c.Path)
					}
					if errDel != nil {
						fmt.Fprintf(stdout, " [ERROR] Failed to delete %s: %v\n", c.Path, errDel)
					} else {
						freed += c.Size
						fmt.Fprintf(stdout, " [DELETED] %s\n", c.Path)
					}
				}
			}
		}
		fmt.Fprintf(stdout, "\nSuccessfully freed %s of disk space!\n", formatBytes(freed))
	} else {
		fmt.Fprintln(stdout, "\nOperation cancelled. No files were deleted.")
	}
}
