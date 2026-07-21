package main

import (
	"bufio"
	"bytes"
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
	"runtime"
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

// RiskClass defines the authoritative risk classification enum
type RiskClass string

const (
	RiskRegenerable    RiskClass = "regenerable"
	RiskPackageManaged RiskClass = "package-managed"
	RiskUserData       RiskClass = "user-data"
	RiskUnknown        RiskClass = "unknown"
)

func (r RiskClass) IsValid() bool {
	switch r {
	case RiskRegenerable, RiskPackageManaged, RiskUserData, RiskUnknown:
		return true
	default:
		return false
	}
}

// Candidate represents a found stale file or directory
type Candidate struct {
	ID             int       `json:"id"`
	Path           string    `json:"path"`
	Size           int64     `json:"size_bytes"`
	AgeDays        float64   `json:"age_days"`
	Category       string    `json:"category"`
	RuleID         string    `json:"rule_id"`
	RiskClass      RiskClass `json:"risk_class"`
	Reason         string    `json:"reason"`
	Evidence       string    `json:"evidence"`
	ProposedAction string    `json:"proposed_action"` // "delete_dir", "delete_file", "uninstall_package", "report-only"
	CanDelete      bool      `json:"can_delete"`
	IsDir          bool      `json:"is_dir"`
	FileCount      int64     `json:"file_count"`
	PackageName    string    `json:"package_name,omitempty"`
	UninstallArgs  []string  `json:"uninstall_args,omitempty"`
	ModTime        time.Time `json:"mod_time"`
}

// Rule defines a single declarative scanning rule
type Rule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Target           string    `json:"target"` // "dir", "file", "any"
	Patterns         []string  `json:"patterns"`
	Category         string    `json:"category"`
	RiskClass        RiskClass `json:"risk_class"`
	MinSizeMB        float64   `json:"min_size_mb,omitempty"`
	MarkerFiles      []string  `json:"marker_files,omitempty"`
	UninstallArgs    []string  `json:"uninstall_args,omitempty"`
	CheckUnusedAtime bool      `json:"check_unused_atime,omitempty"`
}

// Manifest defines the top-level manifest file structure
type Manifest struct {
	DefaultDays      float64 `json:"default_days,omitempty"`
	DefaultMinSizeMB float64 `json:"default_min_size_mb,omitempty"`
	Rules            []Rule  `json:"rules"`
}

// PlanReport defines the structured JSON output for dry-run/plan mode
type PlanReport struct {
	Version   string `json:"version"`
	ScannedAt string `json:"scanned_at"`
	DiskUsage struct {
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
	ExactDirMap map[string][]*Rule // "target" -> []*Rule
	ExtMap      map[string]*Rule   // ".gguf" -> Rule
	GlobRules   []*Rule            // Wildcard & path rules
}

// PackageInventory caches mapped package managers
type PackageInventory struct {
	CargoCrates   map[string]string // binary -> crate
	PipxVenvs     map[string]string // venv -> venv
	NpmPackages   map[string]string // binary/pkg -> pkg
	DotnetTools   map[string]string // binary/tool -> tool
	ComposerPkgs  map[string]string // binary/pkg -> pkg
	ZvmVersions   map[string]string // version -> version
	SdkmanCands   map[string]bool   // "candidate/version" -> true
	SwiftVersions map[string]bool   // version -> true
}

func loadPackageInventory() *PackageInventory {
	inv := &PackageInventory{
		CargoCrates:   make(map[string]string),
		PipxVenvs:     make(map[string]string),
		NpmPackages:   make(map[string]string),
		DotnetTools:   make(map[string]string),
		ComposerPkgs:  make(map[string]string),
		ZvmVersions:   make(map[string]string),
		SdkmanCands:   make(map[string]bool),
		SwiftVersions: make(map[string]bool),
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return inv
	}

	// 1. Cargo inventory: parse ~/.cargo/.crates.toml
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
						inv.CargoCrates[bMatch[1]] = crateName
					}
				}
			}
		}
	}

	// Cargo inventory: parse ~/.cargo/.crates2.json
	cratesJson := filepath.Join(home, ".cargo", ".crates2.json")
	if data, err := os.ReadFile(cratesJson); err == nil {
		var structCrates struct {
			Installs map[string]struct {
				Bins []string `json:"bins"`
			} `json:"installs"`
		}
		if err := json.Unmarshal(data, &structCrates); err == nil {
			for key, val := range structCrates.Installs {
				parts := strings.Fields(key)
				if len(parts) > 0 {
					crateName := parts[0]
					for _, b := range val.Bins {
						inv.CargoCrates[b] = crateName
					}
				}
			}
		}
	}

	// 2. Pipx inventory: parse ~/.local/pipx/venvs
	pipxDir := filepath.Join(home, ".local", "pipx", "venvs")
	if entries, err := os.ReadDir(pipxDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				inv.PipxVenvs[e.Name()] = e.Name()
			}
		}
	}

	// 3. npm inventory: check node_modules in nvm or npm-global
	npmRoots := []string{
		filepath.Join(home, ".nvm", "versions", "node"),
		filepath.Join(home, ".config", "nvm", "versions", "node"),
		filepath.Join(home, ".npm-global", "lib", "node_modules"),
	}
	for _, root := range npmRoots {
		if _, err := os.Stat(root); err == nil {
			filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() && p != root {
					inv.NpmPackages[d.Name()] = d.Name()
				}
				return nil
			})
		}
	}

	// 4. Dotnet tools inventory: parse ~/.dotnet/tools/.store
	dotnetStore := filepath.Join(home, ".dotnet", "tools", ".store")
	if entries, err := os.ReadDir(dotnetStore); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				inv.DotnetTools[e.Name()] = e.Name()
			}
		}
	}

	// 5. Composer inventory: parse composer installed.json
	compInst := filepath.Join(home, ".config", "composer", "vendor", "composer", "installed.json")
	if data, err := os.ReadFile(compInst); err == nil {
		var compStruct struct {
			Packages []struct {
				Name string `json:"name"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(data, &compStruct); err == nil {
			for _, p := range compStruct.Packages {
				inv.ComposerPkgs[p.Name] = p.Name
			}
		}
	}

	// 6. SDKMAN candidate inventory
	sdkDir := filepath.Join(home, ".sdkman", "candidates")
	if cands, err := os.ReadDir(sdkDir); err == nil {
		for _, c := range cands {
			if c.IsDir() {
				candName := c.Name()
				candPath := filepath.Join(sdkDir, candName)
				if vers, err := os.ReadDir(candPath); err == nil {
					for _, v := range vers {
						if v.IsDir() && v.Name() != "current" {
							inv.SdkmanCands[fmt.Sprintf("%s/%s", candName, v.Name())] = true
						}
					}
				}
			}
		}
	}

	// 7. Swiftly toolchains
	swiftDir := filepath.Join(home, ".local", "share", "swiftly", "toolchains")
	if vers, err := os.ReadDir(swiftDir); err == nil {
		for _, v := range vers {
			if v.IsDir() {
				inv.SwiftVersions[v.Name()] = true
			}
		}
	}

	// 8. ZVM Zig toolchains
	zvmDir := filepath.Join(home, ".zvm")
	if vers, err := os.ReadDir(zvmDir); err == nil {
		for _, v := range vers {
			if v.IsDir() && v.Name() != "bin" {
				inv.ZvmVersions[v.Name()] = v.Name()
			}
		}
	}

	return inv
}

func NewRuleEngine(m Manifest) *RuleEngine {
	re := &RuleEngine{
		Rules:       m.Rules,
		ExactDirMap: make(map[string][]*Rule),
		ExtMap:      make(map[string]*Rule),
	}

	for i := range m.Rules {
		r := &m.Rules[i]
		if r.RiskClass == "" || !r.RiskClass.IsValid() {
			if strings.HasPrefix(r.Category, "UNUSED") {
				r.RiskClass = RiskPackageManaged
			} else {
				r.RiskClass = RiskUnknown
			}
		}
		isGlob := false
		for _, pat := range r.Patterns {
			patLower := strings.ToLower(pat)
			if strings.HasPrefix(patLower, "*.") && !strings.Contains(patLower[2:], "/") && !strings.Contains(patLower[2:], "*") {
				re.ExtMap[patLower[1:]] = r
			} else if !strings.Contains(patLower, "*") && !strings.Contains(patLower, "/") {
				re.ExactDirMap[patLower] = append(re.ExactDirMap[patLower], r)
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

func hasMarkerFile(dirPath string, markers []string) bool {
	if len(markers) == 0 {
		return true
	}
	parent := filepath.Dir(dirPath)
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(parent, m)); err == nil {
			return true
		}
		if _, err := os.Stat(filepath.Join(dirPath, m)); err == nil {
			return true
		}
	}
	return false
}

func (re *RuleEngine) MatchDir(name, path string, inv *PackageInventory) (*Rule, string, []string) {
	nameLower := strings.ToLower(name)
	if rules, found := re.ExactDirMap[nameLower]; found {
		for _, rule := range rules {
			if rule.Target == "dir" || rule.Target == "any" {
				if hasMarkerFile(path, rule.MarkerFiles) {
					args := formatUninstallArgs(rule.Category, name, path, inv)
					return rule, name, args
				}
			}
		}
	}
	pathClean := filepath.ToSlash(path)
	for _, rule := range re.GlobRules {
		if rule.Target == "dir" || rule.Target == "any" {
			for _, pat := range rule.Patterns {
				if matchPattern(pathClean, pat) || matchPattern(name, pat) {
					if hasMarkerFile(path, rule.MarkerFiles) {
						args := formatUninstallArgs(rule.Category, name, path, inv)
						return rule, name, args
					}
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

	if !hasMarkerFile(path, matchedRule.MarkerFiles) {
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
				return nil, "", nil
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
		if _, ok := inv.NpmPackages[name]; ok {
			return []string{"npm", "uninstall", "-g", name}
		}
		return nil

	case "UNUSED (pipx)":
		vName := ""
		if strings.Contains(pathClean, "/.local/pipx/venvs/") {
			parts := strings.Split(pathClean, "/.local/pipx/venvs/")
			if len(parts) > 1 {
				vName = strings.Split(parts[1], "/")[0]
			}
		} else if target, err := os.Readlink(path); err == nil {
			targetClean := filepath.ToSlash(target)
			if strings.Contains(targetClean, "/.local/pipx/venvs/") {
				parts := strings.Split(targetClean, "/.local/pipx/venvs/")
				if len(parts) > 1 {
					vName = strings.Split(parts[1], "/")[0]
				}
			}
		}
		if vName != "" {
			if _, ok := inv.PipxVenvs[vName]; ok {
				return []string{"pipx", "uninstall", vName}
			}
		}
		return nil

	case "UNUSED (Swift)":
		if strings.Contains(pathClean, "/.local/share/swiftly/toolchains/") {
			parts := strings.Split(pathClean, "/.local/share/swiftly/toolchains/")
			if len(parts) > 1 {
				version := strings.Split(parts[1], "/")[0]
				if version != "" && inv.SwiftVersions[version] {
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
					key := fmt.Sprintf("%s/%s", candidate, version)
					if version != "current" && inv.SdkmanCands[key] {
						return []string{"sdk", "uninstall", candidate, version}
					}
				}
			}
		}
		return nil

	case "UNUSED (Dotnet)":
		if _, ok := inv.DotnetTools[name]; ok {
			return []string{"dotnet", "tool", "uninstall", "-g", name}
		}
		return nil

	case "UNUSED (Composer)":
		if _, ok := inv.ComposerPkgs[name]; ok {
			return []string{"composer", "global", "remove", name}
		}
		return nil

	case "UNUSED (ZVM)":
		if _, ok := inv.ZvmVersions[name]; ok {
			return []string{"zvm", "remove", name}
		}
		return nil
	}

	return nil
}

// Protected files/directories that MUST NEVER be matched or deleted
var protectedAgentPaths = []string{
	"config.toml", "settings.json", "credentials.json", ".credentials",
	"auth.json", "rules", "skills", "memories", "memory", "knowledge",
}

func isProtected(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, p := range protectedAgentPaths {
		if base == p || strings.Contains(base, p) {
			return true
		}
	}
	return false
}

func containsProtectedPath(targetPath string) bool {
	var foundProtected bool
	err := filepath.WalkDir(targetPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			foundProtected = true
			return filepath.SkipAll
		}
		if isProtected(p) {
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

func getDiskSpace(path string) (totalBytes, usedBytes, freeBytes uint64, err error) {
	return getDiskSpaceSyscall(path)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatUintBytes(b uint64) string {
	return formatBytes(int64(b))
}

func matchPattern(str, pattern string) bool {
	str = strings.ToLower(filepath.ToSlash(str))
	pattern = strings.ToLower(filepath.ToSlash(pattern))
	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
		return strings.Contains(str, pattern)
	}
	return globMatch(pattern, str)
}

func globMatch(pattern, str string) bool {
	px, sx := 0, 0
	nextP, nextS := -1, -1
	for sx < len(str) {
		if px < len(pattern) && (pattern[px] == str[sx] || pattern[px] == '?') {
			px++
			sx++
		} else if px < len(pattern) && pattern[px] == '*' {
			nextP = px
			nextS = sx + 1
			px++
		} else if nextP != -1 {
			px = nextP + 1
			sx = nextS
			nextS++
		} else {
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

func loadManifest(customPath string) (Manifest, error) {
	var data []byte
	var err error

	if customPath != "" {
		data, err = os.ReadFile(customPath)
		if err != nil {
			return Manifest{}, fmt.Errorf("failed to read custom manifest file '%s': %w", customPath, err)
		}
	} else {
		home, _ := os.UserHomeDir()
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" && home != "" {
			xdgConfig = filepath.Join(home, ".config")
		}

		candidates := []string{
			filepath.Join(home, ".unslop.json"),
			filepath.Join(xdgConfig, "unslop", "manifest.json"),
		}

		for _, cand := range candidates {
			if cand != "" {
				if d, errRead := os.ReadFile(cand); errRead == nil {
					data = d
					break
				}
			}
		}

		if len(data) == 0 {
			data = defaultManifestData
		}
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	for i := range m.Rules {
		r := &m.Rules[i]
		if r.RiskClass != "" && !r.RiskClass.IsValid() {
			return Manifest{}, fmt.Errorf("invalid risk_class '%s' in rule '%s'", r.RiskClass, r.ID)
		}
	}

	return m, nil
}

func calculateDynamicMinSizeMB(diskTotalBytes uint64) float64 {
	const minFloorMB = 0.1
	const maxCapMB = 50.0

	if diskTotalBytes == 0 {
		return 10.0
	}

	diskGB := float64(diskTotalBytes) / (1024.0 * 1024.0 * 1024.0)

	if diskGB <= 50.0 {
		return 1.0
	}

	if diskGB >= 1000.0 {
		return maxCapMB
	}

	ratio := math.Log10(diskGB/50.0) / math.Log10(2.0)
	val := 1.0 + ratio*9.0

	if val > maxCapMB {
		return maxCapMB
	}
	return val
}

func getDefaultManifest() Manifest {
	var m Manifest
	_ = json.Unmarshal(defaultManifestData, &m)
	return m
}

func applyOverrides(engine *RuleEngine, args []string) ([]string, []string) {
	var removed []string
	var added []string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			targetID := strings.TrimPrefix(arg, "-")
			filtered := engine.Rules[:0]
			for _, r := range engine.Rules {
				if r.ID != targetID && r.Category != targetID {
					filtered = append(filtered, r)
				} else {
					removed = append(removed, r.ID)
				}
			}
			engine.Rules = filtered
		} else if strings.HasPrefix(arg, "+") && len(arg) > 1 {
			pat := strings.TrimPrefix(arg, "+")
			customRule := Rule{
				ID:        "custom_" + strconv.FormatInt(time.Now().UnixNano(), 10),
				Name:      "Custom User Pattern (" + pat + ")",
				Target:    "any",
				Patterns:  []string{pat},
				Category:  "Custom Pattern",
				RiskClass: RiskUnknown,
			}
			engine.Rules = append(engine.Rules, customRule)
			added = append(added, pat)
		}
	}

	*engine = *NewRuleEngine(Manifest{Rules: engine.Rules})
	return removed, added
}

func getDirStats(dirPath string, now time.Time) (size int64, maxModTime time.Time, fileCount int64) {
	fi, err := os.Lstat(dirPath)
	if err != nil {
		return 0, now, 0
	}
	maxModTime = fi.ModTime()

	filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		fileCount++
		size += info.Size()
		if info.ModTime().After(maxModTime) {
			maxModTime = info.ModTime()
		}
		return nil
	})
	return size, maxModTime, fileCount
}

func renderProgressBar(percentage float64, width int) string {
	if percentage < 0 {
		percentage = 0
	}
	if percentage > 100 {
		percentage = 100
	}
	filled := int(math.Round(percentage / 100.0 * float64(width)))
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func scanParallel(scanDirs []string, engine *RuleEngine, minDays float64, minSizeBytes int64, includeData bool) []Candidate {
	pkgInventory := loadPackageInventory()

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
		if err != nil {
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
						if strings.HasSuffix(strings.ToLower(name), ".sock") ||
							strings.HasSuffix(strings.ToLower(name), ".lock") ||
							strings.HasSuffix(strings.ToLower(name), ".pid") {
							return nil
						}
					}
				}

				atomic.AddInt64(&scannedFiles, 1)

				if d.IsDir() && p != r {
					rule, pkgName, uninstallArgs := engine.MatchDir(name, p, pkgInventory)
					if rule != nil {
						if rule.RiskClass == RiskUserData && !includeData {
							return filepath.SkipDir
						}

						sz, maxModTime, fCount := getDirStats(p, now)
						atomic.AddInt64(&scannedFiles, fCount)

						ageDays := now.Sub(maxModTime).Hours() / 24.0

						reqMinSize := minSizeBytes
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}

						if ageDays >= minDays && sz >= reqMinSize {
							act := "delete_dir"
							canDel := true

							if strings.HasPrefix(rule.Category, "UNUSED") {
								act = "uninstall_package"
								if len(uninstallArgs) == 0 {
									act = "report-only"
									canDel = false
								}
							}

							if rule.RiskClass == RiskUnknown {
								act = "report-only"
								canDel = false
							}

							cand := Candidate{
								Path:           p,
								Size:           sz,
								AgeDays:        ageDays,
								Category:       rule.Category,
								RuleID:         rule.ID,
								RiskClass:      rule.RiskClass,
								Reason:         fmt.Sprintf("%s (stale for %.1fd, %s)", rule.Name, ageDays, formatBytes(sz)),
								Evidence:       fmt.Sprintf("Last modified %.1fd ago (%s)", ageDays, maxModTime.Format("2006-01-02")),
								ProposedAction: act,
								CanDelete:      canDel,
								IsDir:          true,
								FileCount:      fCount,
								PackageName:    pkgName,
								UninstallArgs:  uninstallArgs,
								ModTime:        maxModTime,
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
				} else if !d.IsDir() {
					info, err := d.Info()
					if err != nil {
						return nil
					}
					sz := info.Size()

					if sz < 100*1024 {
						return nil
					}

					rule, pkgName, uninstallArgs := engine.MatchFile(name, p, info, pkgInventory)
					if rule != nil {
						if rule.RiskClass == RiskUserData && !includeData {
							return nil
						}

						ageDays := now.Sub(info.ModTime()).Hours() / 24.0

						reqMinSize := minSizeBytes
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}

						if ageDays >= minDays && sz >= reqMinSize {
							act := "delete_file"
							canDel := true

							if strings.HasPrefix(rule.Category, "UNUSED") {
								act = "uninstall_package"
								if len(uninstallArgs) == 0 {
									act = "report-only"
									canDel = false
								}
							}

							if rule.RiskClass == RiskUnknown {
								act = "report-only"
								canDel = false
							}

							cand := Candidate{
								Path:           p,
								Size:           sz,
								AgeDays:        ageDays,
								Category:       rule.Category,
								RuleID:         rule.ID,
								RiskClass:      rule.RiskClass,
								Reason:         fmt.Sprintf("%s (stale for %.1fd, %s)", rule.Name, ageDays, formatBytes(sz)),
								Evidence:       fmt.Sprintf("Last modified %.1fd ago (%s)", ageDays, info.ModTime().Format("2006-01-02")),
								ProposedAction: act,
								CanDelete:      canDel,
								IsDir:          false,
								FileCount:      1,
								PackageName:    pkgName,
								UninstallArgs:  uninstallArgs,
								ModTime:        info.ModTime(),
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

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Size > candidates[j].Size
	})

	for i := range candidates {
		candidates[i].ID = i + 1
	}

	return candidates
}

func formatNumber(n int64) string {
	in := strconv.FormatInt(n, 10)
	out := make([]byte, 0, len(in)+(len(in)-1)/3)
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func findFzf() string {
	if fzfPath, err := exec.LookPath("fzf"); err == nil {
		return fzfPath
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		altPath := filepath.Join(home, ".local", "bin", "fzf")
		if _, err := os.Stat(altPath); err == nil {
			return altPath
		}
	}
	return ""
}

func runFzfInteractive(candidates []Candidate, fzfBin string, diskTotal, diskUsed, diskFree uint64) []Candidate {
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "No stale candidates found matching criteria.\n")
		return nil
	}

	var totalSizeBytes int64
	for _, c := range candidates {
		totalSizeBytes += c.Size
	}

	var inputBuf strings.Builder
	for _, c := range candidates {
		line := fmt.Sprintf("[%04d] %10s | %4.1fd | %-16s | %s\n", c.ID, formatBytes(c.Size), c.AgeDays, c.Category, c.Path)
		inputBuf.WriteString(line)
	}

	headerStr := fmt.Sprintf(
		"unslop v%s | Total: %s | Used: %s | Free: %s | Candidates: %d (%s)\nControls: TAB/Shift-TAB: Select | Ctrl-A: Select All | Enter: Confirm Selection",
		Version, formatUintBytes(diskTotal), formatUintBytes(diskUsed), formatUintBytes(diskFree),
		len(candidates), formatBytes(totalSizeBytes),
	)

	cmd := exec.Command(fzfBin,
		"--multi",
		"--ansi",
		"--reverse",
		"--height=80%",
		"--header="+headerStr,
		"--prompt=unslop> ",
	)

	cmd.Stdin = strings.NewReader(inputBuf.String())
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil
	}

	selectedLines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(selectedLines) == 0 || selectedLines[0] == "" {
		return nil
	}

	candMap := make(map[int]Candidate)
	for _, c := range candidates {
		candMap[c.ID] = c
	}

	var selected []Candidate
	for _, line := range selectedLines {
		if strings.HasPrefix(line, "[") && len(line) >= 6 {
			idStr := line[1:5]
			if id, err := strconv.Atoi(idStr); err == nil {
				if cand, ok := candMap[id]; ok {
					selected = append(selected, cand)
				}
			}
		}
	}
	return selected
}

func getDefaultScanDirs() []string {
	var dirs []string
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		dirs = append(dirs, home)
	}

	tmpCandidates := []string{
		os.Getenv("TMPDIR"),
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
		"/tmp",
	}

	seen := make(map[string]bool)
	var res []string
	for _, d := range dirs {
		if d != "" {
			p := filepath.Clean(d)
			seen[p] = true
			res = append(res, d)
		}
	}
	for _, d := range tmpCandidates {
		if d != "" {
			p := filepath.Clean(d)
			if !seen[p] {
				if _, err := os.Stat(p); err == nil {
					seen[p] = true
					res = append(res, d)
				}
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
	applyDataFlag := flags.Bool("apply-data", false, "Authorize deletion of user-data items (requires -include-data and -apply)")
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

	if *daysFlag < 0 {
		fmt.Fprintf(stderr, "Error: -days cannot be negative\n")
		return 2
	}

	if *minSizeFlag < 0 {
		fmt.Fprintf(stderr, "Error: -min-size-mb cannot be negative\n")
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

	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(stderr, "Error: scan path '%s' does not exist or is inaccessible: %v\n", p, err)
			return 1
		}
	}

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
	confirmAndDeleteWithIO(selected, isDryRun, *applyDataFlag, *trashFlag, diskUsed, diskFree, stdout, stdin)
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
	if err := moveToTrashOS(path); err == nil {
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	trashFilesDir := filepath.Join(home, ".local", "share", "Trash", "files")
	if runtime.GOOS == "darwin" {
		trashFilesDir = filepath.Join(home, ".Trash")
	}
	if err := os.MkdirAll(trashFilesDir, 0755); err != nil {
		return err
	}

	base := filepath.Base(path)
	dest := filepath.Join(trashFilesDir, base)
	if _, err := os.Stat(dest); err == nil {
		ext := filepath.Ext(base)
		nameNoExt := strings.TrimSuffix(base, ext)
		timeStamp := time.Now().Format("20060102_150405")
		dest = filepath.Join(trashFilesDir, fmt.Sprintf("%s_%s%s", nameNoExt, timeStamp, ext))
	}
	return os.Rename(path, dest)
}

func confirmAndDelete(selected []Candidate, dryRun bool, allowData bool, useTrash bool, diskUsed, diskFree uint64) {
	confirmAndDeleteWithIO(selected, dryRun, allowData, useTrash, diskUsed, diskFree, os.Stdout, os.Stdin)
}

func confirmAndDeleteWithIO(selected []Candidate, dryRun bool, allowData bool, useTrash bool, diskUsed, diskFree uint64, stdout io.Writer, stdin io.Reader) {
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
	fmt.Fprintf(stdout, " STAGED FOR REVIEW: %d items (%s)\n", len(selected), formatBytes(total))
	fmt.Fprintf(stdout, " DISK SAVINGS: %s used -> %s used (Will free %s)\n",
		formatUintBytes(diskUsed), formatBytes(newDiskUsed), formatBytes(total))
	fmt.Fprintf(stdout, "============================================================\n")
	for _, c := range selected {
		kind := "FILE"
		if c.IsDir {
			kind = "DIR "
		}
		statusTag := ""
		if !c.CanDelete || c.RiskClass == RiskUnknown {
			statusTag = " [REPORT-ONLY]"
		} else if c.RiskClass == RiskUserData {
			statusTag = " [REQUIRES -apply-data]"
		}
		fmt.Fprintf(stdout, " [%s: %-13s | RISK: %-16s] %10s | %4.1fd old | %s%s\n", kind, c.Category, c.RiskClass, formatBytes(c.Size), c.AgeDays, c.Path, statusTag)
	}
	fmt.Fprintf(stdout, "============================================================\n")

	if dryRun {
		fmt.Fprintln(stdout, "\n[READ-ONLY PLAN MODE] No files were deleted. Pass '-apply' flag to execute deletion.")
		return
	}

	fmt.Fprintf(stdout, "\nAre you sure you want to proceed with permanent action on these %d items? (y/N): ", len(selected))
	reader := bufio.NewReader(stdin)
	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) == "y" {
		fmt.Fprintln(stdout, "\nExecuting actions...")
		var freed int64
		for _, c := range selected {
			if !c.CanDelete || c.RiskClass == RiskUnknown {
				fmt.Fprintf(stdout, " [SKIP REPORT-ONLY] %s is marked report-only/unknown. Action refused.\n", c.Path)
				continue
			}

			if c.RiskClass == RiskUserData && !allowData {
				fmt.Fprintf(stdout, " [REFUSED] %s is user-data. Pass '-apply-data' flag to authorize deletion.\n", c.Path)
				continue
			}

			info, err := os.Lstat(c.Path)
			if err != nil {
				fmt.Fprintf(stdout, " [SKIP] %s no longer exists on disk.\n", c.Path)
				continue
			}

			if info.IsDir() != c.IsDir {
				fmt.Fprintf(stdout, " [ABORT] File type changed for %s! Skipping.\n", c.Path)
				continue
			}

			if !c.IsDir && info.Size() != c.Size {
				fmt.Fprintf(stdout, " [ABORT] File size changed for %s (scanned: %d B, current: %d B)! Skipping.\n", c.Path, c.Size, info.Size())
				continue
			}

			if !c.ModTime.IsZero() && !info.ModTime().Equal(c.ModTime) {
				fmt.Fprintf(stdout, " [ABORT] File modification time changed for %s! Skipping.\n", c.Path)
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
					fmt.Fprintf(stdout, " Manual cleanup skipped to prevent package database corruption.\n")
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
