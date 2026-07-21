package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
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
	"syscall"
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
	RootModTime    time.Time `json:"root_mod_time"`
}

// Rule defines a single declarative scanning rule
type Rule struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Target              string    `json:"target"` // "dir", "file", "any"
	Patterns            []string  `json:"patterns"`
	Category            string    `json:"category"`
	RiskClass           RiskClass `json:"risk_class"`
	MinSizeMB           float64   `json:"min_size_mb,omitempty"`
	MarkerFiles         []string  `json:"marker_files,omitempty"`
	InternalMarkerFiles []string  `json:"internal_marker_files,omitempty"`
	UninstallArgs       []string  `json:"uninstall_args,omitempty"`
	CheckUnusedAtime    bool      `json:"check_unused_atime,omitempty"`
}

// Manifest defines the top-level manifest file structure
type Manifest struct {
	Version          int     `json:"version,omitempty"`
	DefaultDays      float64 `json:"default_days,omitempty"`
	DefaultMinSizeMB float64 `json:"default_min_size_mb,omitempty"`
	Rules            []Rule  `json:"rules"`
}

// ExecutionResult records detailed action counts and freed space
type ExecutionResult struct {
	Attempted               int   `json:"attempted"`
	Completed               int   `json:"completed"`
	Skipped                 int   `json:"skipped"`
	Aborted                 int   `json:"aborted"`
	Failed                  int   `json:"failed"`
	Freed                   int64 `json:"freed_bytes"`
	FreedPermanently        int64 `json:"freed_permanently_bytes"`
	MovedToTrash            int64 `json:"moved_to_trash_bytes"`
	PackageUninstallSavings int64 `json:"package_uninstall_savings_bytes"`
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

func hasInternalMarkerFile(dirPath string, markers []string) bool {
	if len(markers) == 0 {
		return true
	}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dirPath, m)); err == nil {
			return true
		}
	}
	return false
}

func getDeviceID(path string) (uint64, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), nil
	}
	return 0, nil
}

func containsMountOrReparsePoint(dirPath string) (bool, string, error) {
	rootDev, err := getDeviceID(dirPath)
	if err != nil {
		return false, "", err
	}

	var boundaryPath string
	var boundaryErr error

	errWalk := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == dirPath {
			return nil
		}

		fi, errInfo := d.Info()
		if errInfo != nil {
			return nil
		}

		if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 {
			boundaryPath = path
			boundaryErr = fmt.Errorf("reparse point or symlink boundary detected at %s", path)
			return filepath.SkipDir
		}

		if rootDev != 0 {
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
				if uint64(stat.Dev) != rootDev {
					boundaryPath = path
					boundaryErr = fmt.Errorf("cross-filesystem mount boundary detected at %s", path)
					return filepath.SkipDir
				}
			}
		}

		return nil
	})

	if boundaryPath != "" {
		return true, boundaryPath, boundaryErr
	}
	return false, "", errWalk
}

func (re *RuleEngine) MatchDir(name, path string, inv *PackageInventory) (*Rule, string, []string) {
	nameLower := strings.ToLower(name)
	if rules, found := re.ExactDirMap[nameLower]; found {
		for _, rule := range rules {
			if rule.Target == "dir" || rule.Target == "any" {
				if hasMarkerFile(path, rule.MarkerFiles) && hasInternalMarkerFile(path, rule.InternalMarkerFiles) {
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
					if hasMarkerFile(path, rule.MarkerFiles) && hasInternalMarkerFile(path, rule.InternalMarkerFiles) {
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
		atime, _, _, isPosix := getStatTimes(info)
		if isPosix && !atime.IsZero() {
			if time.Since(atime) < 7*24*time.Hour {
				return nil, "", nil
			}
		} else {
			if time.Since(info.ModTime()) < 7*24*time.Hour {
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
		if base == p {
			return true
		}
	}
	return false
}

func isPackageRegistryInternalPath(path string) bool {
	pathClean := filepath.ToSlash(path)
	return strings.Contains(pathClean, "/.cargo/registry/") ||
		strings.Contains(pathClean, "/.cargo/git/") ||
		strings.Contains(pathClean, "/.local/pipx/") ||
		strings.Contains(pathClean, "/.npm/") ||
		strings.Contains(pathClean, "/.cache/pypoetry/") ||
		strings.Contains(pathClean, "/.cache/yarn/") ||
		strings.Contains(pathClean, "/.gradle/caches/")
}

func getEffectiveItemTime(info os.FileInfo) time.Time {
	mtime := info.ModTime()
	if mtime.Before(time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)) {
		atime, ctime, _, isPosix := getStatTimes(info)
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

func validateManifest(m Manifest) error {
	if m.Version > 1 {
		return fmt.Errorf("unsupported manifest version %d (supported max version: 1)", m.Version)
	}

	seenIDs := make(map[string]bool)
	seenPatterns := make(map[string]string)

	for _, r := range m.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("manifest rule contains empty 'id'")
		}
		if seenIDs[r.ID] {
			return fmt.Errorf("duplicate rule ID '%s' found in manifest", r.ID)
		}
		seenIDs[r.ID] = true

		if r.Target != "dir" && r.Target != "file" && r.Target != "any" {
			return fmt.Errorf("rule '%s' has invalid target '%s' (must be 'dir', 'file', or 'any')", r.ID, r.Target)
		}

		if len(r.Patterns) == 0 {
			return fmt.Errorf("rule '%s' must have at least one pattern in 'patterns'", r.ID)
		}

		for _, pat := range r.Patterns {
			if strings.TrimSpace(pat) == "" {
				return fmt.Errorf("rule '%s' contains empty pattern string", r.ID)
			}
			key := fmt.Sprintf("%s:%s", r.Target, pat)
			if existingRule, exists := seenPatterns[key]; exists {
				fmt.Fprintf(os.Stderr, "[MANIFEST WARNING] Rule '%s' pattern '%s' (target: %s) conflicts with rule '%s'.\n", r.ID, pat, r.Target, existingRule)
			} else {
				seenPatterns[key] = r.ID
			}
		}
	}
	return nil
}

func readManifestBytes(customPath string) ([]byte, error) {
	if customPath != "" {
		data, err := os.ReadFile(customPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read custom manifest file '%s': %w", customPath, err)
		}
		return data, nil
	}

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
				return d, nil
			}
		}
	}

	return defaultManifestData, nil
}

func loadManifest(customPath string) (Manifest, error) {
	data, err := readManifestBytes(customPath)
	if err != nil {
		return Manifest{}, err
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	for i := range m.Rules {
		r := &m.Rules[i]
		if r.RiskClass == "" {
			fmt.Fprintf(os.Stderr, "[MANIFEST DIAGNOSTIC] Rule '%s' (%s) missing explicit risk_class. Migrated to 'unknown'. Please explicitly classify risk_class in manifest.\n", r.ID, r.Name)
			r.RiskClass = RiskUnknown
		} else if !r.RiskClass.IsValid() {
			return Manifest{}, fmt.Errorf("invalid risk_class '%s' in rule '%s'", r.RiskClass, r.ID)
		}
	}

	if m.Version == 0 {
		m.Version = 1
	}

	if errVal := validateManifest(m); errVal != nil {
		return Manifest{}, fmt.Errorf("manifest validation failed: %w", errVal)
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

func inspectDirectorySubtree(dirPath string, now time.Time) (size int64, maxModTime time.Time, fileCount int64, hasProtected bool, err error) {
	fi, errLstat := os.Lstat(dirPath)
	if errLstat != nil {
		return 0, now, 0, true, errLstat
	}
	maxModTime = fi.ModTime()

	if isProtected(dirPath) {
		hasProtected = true
	}

	var walkErr error
	errWalk := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			walkErr = err
			hasProtected = true
			return filepath.SkipAll
		}
		if isProtected(path) {
			hasProtected = true
		}
		info, errInfo := d.Info()
		if errInfo != nil {
			walkErr = errInfo
			hasProtected = true
			return filepath.SkipAll
		}
		fileCount++
		size += info.Size()

		itemTime := getEffectiveItemTime(info)
		if itemTime.After(maxModTime) {
			maxModTime = itemTime
		}
		return nil
	})

	if errWalk != nil {
		return size, maxModTime, fileCount, true, errWalk
	}
	if walkErr != nil {
		return size, maxModTime, fileCount, true, walkErr
	}
	return size, maxModTime, fileCount, hasProtected, nil
}

func getDirStats(dirPath string, now time.Time) (size int64, maxModTime time.Time, fileCount int64, err error) {
	sz, maxMod, count, _, err := inspectDirectorySubtree(dirPath, now)
	return sz, maxMod, count, err
}

func rollbackQuarantine(origPath, quarantinePath string, out ...io.Writer) error {
	if _, err := os.Lstat(quarantinePath); os.IsNotExist(err) {
		return nil
	}

	destPath := origPath
	isOccupied := false

	if _, errStat := os.Lstat(origPath); errStat == nil {
		isOccupied = true
		nowNano := time.Now().UnixNano()
		destPath = fmt.Sprintf("%s.restored-%d", origPath, nowNano)
		counter := 1
		for {
			if _, errDest := os.Lstat(destPath); os.IsNotExist(errDest) {
				break
			}
			destPath = fmt.Sprintf("%s.restored-%d-%d", origPath, nowNano, counter)
			counter++
		}
	}

	if errRename := os.Rename(quarantinePath, destPath); errRename != nil {
		return errRename
	}

	if isOccupied {
		var w io.Writer = os.Stdout
		if len(out) > 0 && out[0] != nil {
			w = out[0]
		}
		fmt.Fprintf(w, " [ROLLBACK COLLISION] Original path '%s' is occupied! Restored quarantine to collision-safe path '%s'\n", origPath, destPath)
	}

	return nil
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

func determineCandidateAction(rule *Rule, isDir bool, uninstallArgs []string, includeData bool, containsProtected bool) (string, bool) {
	if containsProtected {
		return "report-only", false
	}

	defaultDeleteAction := "delete_file"
	if isDir {
		defaultDeleteAction = "delete_dir"
	}

	switch rule.RiskClass {
	case RiskRegenerable:
		return defaultDeleteAction, true

	case RiskPackageManaged:
		// Package uninstallation remains report-only for initial public alpha to ensure multi-binary safety
		return "report-only", false

	case RiskUserData:
		if includeData {
			return defaultDeleteAction, true
		}
		return "report-only", false

	case RiskUnknown:
		return "report-only", false

	default:
		return "report-only", false
	}
}

type QuarantineJournalEntry struct {
	OpID           string    `json:"op_id"`
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path"`
	Phase          string    `json:"phase"`
	Timestamp      time.Time `json:"timestamp"`
}

var (
	journalMutex        sync.Mutex
	journalPathOverride string
)

func getJournalPath() string {
	if journalPathOverride != "" {
		return journalPathOverride
	}
	if env := os.Getenv("UNSLOP_JOURNAL_PATH"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".unslop-journal.json"
	}
	return filepath.Join(home, ".unslop-journal.json")
}

func loadJournal(jPath string) ([]QuarantineJournalEntry, error) {
	journalMutex.Lock()
	defer journalMutex.Unlock()

	data, err := os.ReadFile(jPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []QuarantineJournalEntry{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []QuarantineJournalEntry{}, nil
	}
	var entries []QuarantineJournalEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func saveJournal(jPath string, entries []QuarantineJournalEntry) error {
	journalMutex.Lock()
	defer journalMutex.Unlock()

	dir := filepath.Dir(jPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(jPath, data, 0600)
}

func recordQuarantineEntry(jPath string, entry QuarantineJournalEntry) error {
	entries, err := loadJournal(jPath)
	if err != nil {
		entries = []QuarantineJournalEntry{}
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	updated := false
	for i, e := range entries {
		if e.OpID == entry.OpID {
			entries[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		entries = append(entries, entry)
	}
	return saveJournal(jPath, entries)
}

func updateJournalEntryPhase(jPath string, opID string, phase string) error {
	entries, err := loadJournal(jPath)
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.OpID == opID {
			entries[i].Phase = phase
			return saveJournal(jPath, entries)
		}
	}
	return nil
}

func removeJournalEntry(jPath string, opID string) error {
	entries, err := loadJournal(jPath)
	if err != nil {
		return err
	}
	newEntries := make([]QuarantineJournalEntry, 0, len(entries))
	for _, e := range entries {
		if e.OpID != opID {
			newEntries = append(newEntries, e)
		}
	}
	return saveJournal(jPath, newEntries)
}

func isPathUnderAny(path string, scanDirs []string) bool {
	if len(scanDirs) == 0 {
		return true
	}
	pAbs, err := filepath.Abs(path)
	if err != nil {
		pAbs = filepath.Clean(path)
	}
	for _, root := range scanDirs {
		r := root
		if strings.HasPrefix(root, "~") {
			home, _ := os.UserHomeDir()
			if home != "" {
				r = filepath.Join(home, root[1:])
			}
		}
		rAbs, err := filepath.Abs(r)
		if err != nil {
			rAbs = filepath.Clean(r)
		}
		if pAbs == rAbs || strings.HasPrefix(pAbs, rAbs+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func recoverOrphanedQuarantines(scanDirs []string, out io.Writer) int {
	recoveredCount := 0
	jPath := getJournalPath()
	entries, err := loadJournal(jPath)
	if err != nil || len(entries) == 0 {
		return 0
	}

	remainingEntries := make([]QuarantineJournalEntry, 0, len(entries))
	for _, entry := range entries {
		if len(scanDirs) > 0 && !isPathUnderAny(entry.QuarantinePath, scanDirs) && !isPathUnderAny(entry.OriginalPath, scanDirs) {
			remainingEntries = append(remainingEntries, entry)
			continue
		}

		if entry.QuarantinePath == "" {
			continue
		}

		if _, errStat := os.Lstat(entry.QuarantinePath); os.IsNotExist(errStat) {
			// Quarantine path no longer exists on disk; clean up stale journal entry
			continue
		}

		origPath := entry.OriginalPath
		if origPath == "" {
			idx := strings.Index(entry.QuarantinePath, ".unslop-quarantine-")
			if idx != -1 {
				origPath = entry.QuarantinePath[:idx]
			}
		}

		if origPath == "" {
			remainingEntries = append(remainingEntries, entry)
			continue
		}

		if errRB := rollbackQuarantine(origPath, entry.QuarantinePath, out); errRB == nil {
			recoveredCount++
			fmt.Fprintf(out, "[QUARANTINE RECOVERY] Restored orphaned quarantine '%s'\n", entry.QuarantinePath)
		} else {
			fmt.Fprintf(out, "[QUARANTINE ERROR] Failed to restore orphaned quarantine '%s': %v\n", entry.QuarantinePath, errRB)
			remainingEntries = append(remainingEntries, entry)
		}
	}

	_ = saveJournal(jPath, remainingEntries)
	return recoveredCount
}

func countFilesInSubtree(dirPath string) int64 {
	var count int64
	_ = filepath.WalkDir(dirPath, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			count++
		}
		return nil
	})
	return count
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

		if rule, _, _ := engine.MatchDir(fi.Name(), p, pkgInventory); rule != nil {
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

	var completedRoots int64
	totalRoots := int64(len(topLevelPaths))

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
				bar := renderProgressBar(100.0, 20)
				fmt.Fprintf(os.Stderr, "\r\033[KScanning %s 100%% | %s files | Candidates: %d (%s)\n",
					bar, formatNumber(sFiles), cCount, formatBytes(cBytes))
				return
			case <-ticker.C:
				sFiles := atomic.LoadInt64(&scannedFiles)
				cBytes := atomic.LoadInt64(&candidateBytes)
				cCount := atomic.LoadInt64(&candidateCount)
				cRoots := atomic.LoadInt64(&completedRoots)

				elapsedSec := time.Since(startTime).Seconds()
				filesPerSec := 0.0
				if elapsedSec > 0 {
					filesPerSec = float64(sFiles) / elapsedSec
				}

				pct := 0.0
				if totalRoots > 0 {
					pct = (float64(cRoots) / float64(totalRoots)) * 95.0
				}
				if pct > 95.0 {
					pct = 95.0
				}
				bar := renderProgressBar(pct, 20)

				fmt.Fprintf(os.Stderr, "\r\033[KScanning %s %3.0f%% | %s files (%.0f/s) | Candidates: %d (%s)",
					bar, pct, formatNumber(sFiles), filesPerSec, cCount, formatBytes(cBytes))
			}
		}
	}()

	sem := make(chan struct{}, 16)

	for _, targetPath := range topLevelPaths {
		walkWg.Add(1)
		go func(r string) {
			defer walkWg.Done()
			defer atomic.AddInt64(&completedRoots, 1)
			sem <- struct{}{}
			defer func() { <-sem }()

			isTmp := r == "/tmp" || strings.HasPrefix(r, "/tmp/")

			filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
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

				if isProtected(p) {
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
						_, _, uid, isPosix := getStatTimes(info)
						if isPosix && uid != currentUID {
							if d.IsDir() {
								atomic.AddInt64(&scannedFiles, countFilesInSubtree(p))
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

				if d.IsDir() {
					rule, pkgName, uninstallArgs := engine.MatchDir(name, p, pkgInventory)
					if rule != nil {
						if rule.RiskClass == RiskUserData && !includeData {
							atomic.AddInt64(&scannedFiles, countFilesInSubtree(p))
							return filepath.SkipDir
						}
						sz, maxModTime, fCount, hasProt, _ := inspectDirectorySubtree(p, now)
						act, canDel := determineCandidateAction(rule, true, uninstallArgs, includeData, hasProt)

						rootFi, errStat := d.Info()
						var rootModTime time.Time
						if errStat == nil {
							rootModTime = rootFi.ModTime()
						}

						atomic.AddInt64(&scannedFiles, fCount)

						ageDays := now.Sub(maxModTime).Hours() / 24.0

						reqMinSize := minSizeBytes
						if rule.MinSizeMB > 0 {
							reqMinSize = int64(rule.MinSizeMB * 1024 * 1024)
						}

						if ageDays >= minDays && sz >= reqMinSize {
							cand := Candidate{
								Path:           p,
								Size:           sz,
								AgeDays:        ageDays,
								Category:       rule.Category,
								RuleID:         rule.ID,
								RiskClass:      rule.RiskClass,
								Reason:         fmt.Sprintf("%s (stale for %.1fd, %s)", rule.Name, ageDays, formatBytes(sz)),
								Evidence:       fmt.Sprintf("Size: %s, Age: %.1fd, Files: %d", formatBytes(sz), ageDays, fCount),
								ProposedAction: act,
								CanDelete:      canDel,
								IsDir:          true,
								FileCount:      fCount,
								PackageName:    pkgName,
								UninstallArgs:  uninstallArgs,
								ModTime:        maxModTime,
								RootModTime:    rootModTime,
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
					if isPackageRegistryInternalPath(p) {
						return nil
					}
					info, err := d.Info()
					if err != nil {
						return nil
					}
					sz := info.Size()

					rule, pkgName, uninstallArgs := engine.MatchFile(name, p, info, pkgInventory)
					if rule != nil {
						if rule.RiskClass == RiskUserData && !includeData {
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

						lastActivity := getEffectiveItemTime(info)
						ageDays := now.Sub(lastActivity).Hours() / 24.0
						if ageDays < 0 {
							ageDays = 0
						}

						if ageDays >= minDays && sz >= reqMinSize {
							cand := Candidate{
								Path:           p,
								Size:           sz,
								AgeDays:        ageDays,
								Category:       rule.Category,
								RuleID:         rule.ID,
								RiskClass:      rule.RiskClass,
								Reason:         fmt.Sprintf("%s (stale for %.1fd, %s)", rule.Name, ageDays, formatBytes(sz)),
								Evidence:       fmt.Sprintf("Last activity %.1fd ago (%s)", ageDays, lastActivity.Format("2006-01-02")),
								ProposedAction: act,
								CanDelete:      canDel,
								IsDir:          false,
								FileCount:      1,
								PackageName:    pkgName,
								UninstallArgs:  uninstallArgs,
								ModTime:        lastActivity,
								RootModTime:    lastActivity,
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

var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?(\x07|\x1b\\)`)

func sanitizeTerminalString(s string) string {
	cleaned := reANSI.ReplaceAllString(s, "")
	var sb strings.Builder
	sb.Grow(len(cleaned))
	for _, r := range cleaned {
		if r == '\n' {
			sb.WriteString(`\n`)
		} else if r == '\r' {
			sb.WriteString(`\r`)
		} else if r == '\t' {
			sb.WriteString(`\t`)
		} else if r < 0x20 || r == 0x7f {
			sb.WriteRune('?')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
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

	candMap := make(map[string]Candidate, len(candidates))
	var inputBuf bytes.Buffer

	for _, c := range candidates {
		token := fmt.Sprintf("cand-%d", c.ID)
		candMap[token] = c

		sanitizedPath := sanitizeTerminalString(c.Path)
		sanitizedCategory := sanitizeTerminalString(c.Category)
		displayLine := fmt.Sprintf("[%d] %10s | %4.1fd | %-16s | %s", c.ID, formatBytes(c.Size), c.AgeDays, sanitizedCategory, sanitizedPath)

		inputBuf.WriteString(token)
		inputBuf.WriteByte('\t')
		inputBuf.WriteString(displayLine)
		inputBuf.WriteByte(0)
	}

	headerStr := fmt.Sprintf(
		"unslop v%s | Total: %s | Used: %s | Free: %s | Candidates: %d (%s)\nControls: TAB/Shift-TAB: Select | Ctrl-A: Select All | Enter: Confirm Selection",
		Version, formatUintBytes(diskTotal), formatUintBytes(diskUsed), formatUintBytes(diskFree),
		len(candidates), formatBytes(totalSizeBytes),
	)

	cmd := exec.Command(fzfBin,
		"--multi",
		"--read0",
		"--print0",
		"--delimiter=\t",
		"--with-nth=2..",
		"--ansi",
		"--reverse",
		"--height=80%",
		"--header="+headerStr,
		"--prompt=unslop> ",
	)

	cmd.Stdin = &inputBuf
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil
	}

	rawOutput := outBuf.Bytes()
	if len(rawOutput) == 0 {
		return nil
	}

	items := bytes.Split(rawOutput, []byte{0})
	var selected []Candidate

	for _, item := range items {
		itemStr := strings.TrimSpace(string(item))
		if itemStr == "" {
			continue
		}
		parts := strings.SplitN(itemStr, "\t", 2)
		token := parts[0]
		if cand, ok := candMap[token]; ok {
			selected = append(selected, cand)
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
	trashFlag := flags.Bool("trash", true, "Move to Trash instead of permanent deletion")
	forcePermanentFlag := flags.Bool("force-permanent", false, "Bypass trash bin and permanently delete items immediately")
	recoverQuarantineFlag := flags.Bool("recover-quarantine", false, "Scan directories and restore orphaned quarantine items from interrupted runs")
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
		fmt.Fprintf(stderr, "  unslop -recover-quarantine (Restore orphaned quarantine items from interrupted runs)\n")
	}

	knownFlagsWithValue := map[string]bool{
		"days":        true,
		"min-size-mb": true,
		"manifest":    true,
		"plan-out":    true,
		"path":        true,
	}
	knownBoolFlags := map[string]bool{
		"dry-run":            true,
		"apply":              true,
		"apply-data":         true,
		"json":               true,
		"include-data":       true,
		"trash":              true,
		"force-permanent":    true,
		"recover-quarantine": true,
		"version":            true,
		"help":               true,
		"h":                  true,
	}

	var flagArgs []string
	var overrideArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "+") {
			overrideArgs = append(overrideArgs, arg)
			continue
		}

		if strings.HasPrefix(arg, "-") {
			rawName := strings.TrimLeft(arg, "-")
			name := rawName
			if idx := strings.Index(rawName, "="); idx != -1 {
				name = rawName[:idx]
			}

			if knownBoolFlags[name] {
				flagArgs = append(flagArgs, arg)
				continue
			}
			if knownFlagsWithValue[name] {
				flagArgs = append(flagArgs, arg)
				if !strings.Contains(rawName, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.HasPrefix(args[i+1], "+") {
					i++
					flagArgs = append(flagArgs, args[i])
				}
				continue
			}

			overrideArgs = append(overrideArgs, arg)
			continue
		}

		overrideArgs = append(overrideArgs, arg)
	}

	if err := flags.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
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

	if *recoverQuarantineFlag {
		cnt := recoverOrphanedQuarantines(scanDirs, stdout)
		fmt.Fprintf(stdout, "Quarantine recovery completed: %d items restored.\n", cnt)
		return 0
	}

	manifest, err := loadManifest(*manifestFlag)
	if err != nil {
		fmt.Fprintf(stderr, "[FATAL] %v\n", err)
		return 1
	}

	engine := NewRuleEngine(manifest)
	allOverrides := append(overrideArgs, flags.Args()...)
	applyOverrides(engine, allOverrides)

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
	useTrash := *trashFlag && !*forcePermanentFlag
	res := confirmAndDeleteWithIO(selected, isDryRun, *applyDataFlag, useTrash, diskUsed, diskFree, stdout, stdin)
	if res.Failed > 0 || res.Aborted > 0 {
		return 1
	}
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

func pathOrInfoExists(destPath, trashInfoPath, trashInfoDir string) bool {
	if _, err := os.Lstat(destPath); err == nil {
		return true
	}
	if trashInfoDir != "" {
		if _, err := os.Lstat(trashInfoPath); err == nil {
			return true
		}
	}
	return false
}

func findUniqueTrashDest(trashFilesDir, trashInfoDir, base string) (string, string, string, string) {
	ext := filepath.Ext(base)
	nameNoExt := strings.TrimSuffix(base, ext)

	destName := base
	destPath := filepath.Join(trashFilesDir, destName)
	trashInfoName := destName + ".trashinfo"
	trashInfoPath := filepath.Join(trashInfoDir, trashInfoName)

	if !pathOrInfoExists(destPath, trashInfoPath, trashInfoDir) {
		return destPath, destName, trashInfoPath, trashInfoName
	}

	counter := 1
	now := time.Now()
	timeStamp := now.Format("20060102_150405")
	for {
		if counter == 1 {
			destName = fmt.Sprintf("%s_%s%s", nameNoExt, timeStamp, ext)
		} else {
			destName = fmt.Sprintf("%s_%s_%d%s", nameNoExt, timeStamp, counter, ext)
		}
		destPath = filepath.Join(trashFilesDir, destName)
		trashInfoName = destName + ".trashinfo"
		trashInfoPath = filepath.Join(trashInfoDir, trashInfoName)

		if !pathOrInfoExists(destPath, trashInfoPath, trashInfoDir) {
			return destPath, destName, trashInfoPath, trashInfoName
		}
		counter++
	}
}

func copyFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		linkTarget, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(linkTarget, dst)
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyDirTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcChild := filepath.Join(src, entry.Name())
		dstChild := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDirTree(srcChild, dstChild); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcChild, dstChild); err != nil {
				return err
			}
		}
	}
	return nil
}

func movePath(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	info, errStat := os.Lstat(src)
	if errStat != nil {
		return errStat
	}

	if info.IsDir() {
		if errCopy := copyDirTree(src, dst); errCopy != nil {
			_ = os.RemoveAll(dst)
			return errCopy
		}
		return os.RemoveAll(src)
	}

	if errCopy := copyFile(src, dst); errCopy != nil {
		_ = os.Remove(dst)
		return errCopy
	}
	return os.Remove(src)
}

func moveToTrash(path string, originalPath ...string) error {
	orig := path
	if len(originalPath) > 0 && originalPath[0] != "" {
		orig = originalPath[0]
	} else {
		idx := strings.Index(path, ".unslop-quarantine-")
		if idx != -1 && idx > 0 {
			orig = path[:idx]
		}
	}

	workPath := path
	if workPath != orig {
		if _, err := os.Lstat(workPath); err == nil {
			if _, errOrig := os.Lstat(orig); os.IsNotExist(errOrig) {
				if errRename := os.Rename(workPath, orig); errRename == nil {
					workPath = orig
				}
			}
		}
	}

	if err := moveToTrashOS(workPath); err == nil {
		if _, errStat := os.Lstat(workPath); os.IsNotExist(errStat) {
			return nil
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	trashFilesDir := filepath.Join(home, ".local", "share", "Trash", "files")
	trashInfoDir := filepath.Join(home, ".local", "share", "Trash", "info")
	if runtime.GOOS == "darwin" {
		trashFilesDir = filepath.Join(home, ".Trash")
		trashInfoDir = ""
	} else {
		if err := os.MkdirAll(trashInfoDir, 0700); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(trashFilesDir, 0700); err != nil {
		return err
	}

	absPath, errAbs := filepath.Abs(orig)
	if errAbs != nil {
		absPath = orig
	}

	base := filepath.Base(orig)
	destPath, _, trashInfoPath, _ := findUniqueTrashDest(trashFilesDir, trashInfoDir, base)

	var writtenInfoPath string
	if runtime.GOOS == "linux" && trashInfoDir != "" {
		infoContent := fmt.Sprintf("[Trash Info]\nPath=%s\nDeletionDate=%s\n",
			url.PathEscape(absPath), time.Now().Format("2006-01-02T15:04:05"))
		if err := os.WriteFile(trashInfoPath, []byte(infoContent), 0600); err != nil {
			return fmt.Errorf("failed to write trashinfo metadata: %w", err)
		}
		writtenInfoPath = trashInfoPath
	}

	if errMove := movePath(workPath, destPath); errMove != nil {
		if writtenInfoPath != "" {
			_ = os.Remove(writtenInfoPath)
		}
		return fmt.Errorf("failed to move item to trash destination: %w", errMove)
	}

	if _, errStat := os.Lstat(workPath); !os.IsNotExist(errStat) {
		_ = os.RemoveAll(destPath)
		if writtenInfoPath != "" {
			_ = os.Remove(writtenInfoPath)
		}
		return fmt.Errorf("postcondition validation failed: source %s still exists after move to trash", workPath)
	}

	return nil
}

func confirmAndDelete(selected []Candidate, dryRun bool, allowData bool, useTrash bool, diskUsed, diskFree uint64) ExecutionResult {
	return confirmAndDeleteWithIO(selected, dryRun, allowData, useTrash, diskUsed, diskFree, os.Stdout, os.Stdin)
}

func confirmAndDeleteWithIO(selected []Candidate, dryRun bool, allowData bool, useTrash bool, diskUsed, diskFree uint64, stdout io.Writer, stdin io.Reader) ExecutionResult {
	res := ExecutionResult{
		Attempted: len(selected),
	}

	if len(selected) == 0 {
		fmt.Fprintln(stdout, "No items selected. Exiting.")
		return res
	}

	var actionable []Candidate
	var reportOnly []Candidate
	for _, c := range selected {
		if c.CanDelete && c.ProposedAction != "report-only" {
			actionable = append(actionable, c)
		} else {
			reportOnly = append(reportOnly, c)
		}
	}

	var totalActionable int64
	for _, c := range actionable {
		totalActionable += c.Size
	}

	newDiskUsed := int64(diskUsed) - totalActionable
	if newDiskUsed < 0 {
		newDiskUsed = 0
	}

	if len(actionable) > 0 {
		fmt.Fprintf(stdout, "\n============================================================\n")
		fmt.Fprintf(stdout, " STAGED FOR REVIEW: %d items (%s)\n", len(actionable), formatBytes(totalActionable))
		if useTrash {
			fmt.Fprintf(stdout, " DISK SAVINGS: Move to Trash (%s staged; use -force-permanent to reclaim space)\n", formatBytes(totalActionable))
		} else {
			fmt.Fprintf(stdout, " DISK SAVINGS: %s used -> %s used (Will free %s)\n",
				formatUintBytes(diskUsed), formatBytes(newDiskUsed), formatBytes(totalActionable))
		}
		fmt.Fprintf(stdout, "============================================================\n")
		for _, c := range actionable {
			kind := "FILE"
			if c.IsDir {
				kind = "DIR "
			}
			statusTag := ""
			if c.RiskClass == RiskUserData {
				statusTag = " [REQUIRES -apply-data]"
			}
			fmt.Fprintf(stdout, " [%s: %-13s | RISK: %-16s] %10s | %4.1fd old | %s%s\n", kind, c.Category, c.RiskClass, formatBytes(c.Size), c.AgeDays, c.Path, statusTag)
		}
		fmt.Fprintf(stdout, "============================================================\n")
	}

	if len(reportOnly) > 0 {
		var totalReportOnly int64
		for _, c := range reportOnly {
			totalReportOnly += c.Size
		}
		fmt.Fprintf(stdout, "\n============================================================\n")
		fmt.Fprintf(stdout, " REPORT-ONLY / INFORMATIONAL (No Deletion Staged): %d items (%s)\n", len(reportOnly), formatBytes(totalReportOnly))
		fmt.Fprintf(stdout, "============================================================\n")
		for _, c := range reportOnly {
			kind := "FILE"
			if c.IsDir {
				kind = "DIR "
			}
			fmt.Fprintf(stdout, " [%s: %-13s | RISK: %-16s] %10s | %4.1fd old | %s [REPORT-ONLY]\n", kind, c.Category, c.RiskClass, formatBytes(c.Size), c.AgeDays, c.Path)
		}
		fmt.Fprintf(stdout, "============================================================\n")
	}

	if dryRun {
		fmt.Fprintln(stdout, "\n[READ-ONLY PLAN MODE] No files were deleted. Pass '-apply' flag to execute deletion.")
		res.Skipped = len(selected)
		return res
	}

	if len(actionable) == 0 {
		fmt.Fprintln(stdout, "\nNo actionable items eligible for deletion. Exiting.")
		res.Skipped = len(selected)
		return res
	}

	fmt.Fprintf(stdout, "\nAre you sure you want to proceed with permanent action on these %d items? (y/N): ", len(actionable))
	reader := bufio.NewReader(stdin)
	ans, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) != "y" {
		fmt.Fprintln(stdout, "\nOperation cancelled. No files were deleted.")
		res.Skipped = len(selected)
		return res
	}

	fmt.Fprintln(stdout, "\nExecuting actions...")

	res.Skipped += len(reportOnly)

	for _, c := range actionable {
		info, err := os.Lstat(c.Path)
		if err != nil {
			fmt.Fprintf(stdout, " [SKIP] %s no longer exists on disk.\n", c.Path)
			res.Skipped++
			continue
		}

		if info.IsDir() != c.IsDir {
			fmt.Fprintf(stdout, " [ABORT] File type changed for %s! Skipping.\n", c.Path)
			res.Aborted++
			continue
		}

		if !c.IsDir && info.Size() != c.Size {
			fmt.Fprintf(stdout, " [ABORT] File size changed for %s (scanned: %d B, current: %d B)! Skipping.\n", c.Path, c.Size, info.Size())
			res.Aborted++
			continue
		}

		// Revalidate root entry modification timestamp
		if !c.RootModTime.IsZero() && !info.ModTime().Equal(c.RootModTime) {
			fmt.Fprintf(stdout, " [ABORT] Root modification time changed for %s! Skipping.\n", c.Path)
			res.Aborted++
			continue
		}

		if !c.IsDir && !c.ModTime.IsZero() && !info.ModTime().Equal(c.ModTime) {
			fmt.Fprintf(stdout, " [ABORT] File modification time changed for %s! Skipping.\n", c.Path)
			res.Aborted++
			continue
		}

		if c.IsDir && containsProtectedPath(c.Path) {
			fmt.Fprintf(stdout, " [PROTECTED SAFEGUARD] %s contains protected credential/config files inside. Refusing deletion!\n", c.Path)
			res.Aborted++
			continue
		}

		if c.RiskClass == RiskUserData && !allowData {
			fmt.Fprintf(stdout, " [REFUSED] %s is user-data. Pass '-apply-data' flag to authorize deletion.\n", c.Path)
			res.Skipped++
			continue
		}

		// Recalculate and validate policy authoritatively at execution time
		rule := &Rule{RiskClass: c.RiskClass, Category: c.Category}
		authAction, canDel := determineCandidateAction(rule, c.IsDir, c.UninstallArgs, allowData, false)

		if !canDel || authAction == "report-only" {
			fmt.Fprintf(stdout, " [SKIP REPORT-ONLY] %s is marked report-only (RiskClass: %s). Action refused.\n", c.Path, c.RiskClass)
			res.Skipped++
			continue
		}

		switch authAction {
		case "uninstall_package":
			if len(c.UninstallArgs) == 0 {
				fmt.Fprintf(stdout, " [SKIP REPORT-ONLY] %s has no uninstaller arguments. Action refused.\n", c.Path)
				res.Skipped++
				continue
			}
			execStr := strings.Join(c.UninstallArgs, " ")
			fmt.Fprintf(stdout, " [UNINSTALLING: %s] Running '%s'...\n", c.Category, execStr)
			cmd := exec.Command(c.UninstallArgs[0], c.UninstallArgs[1:]...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Fprintf(stdout, " [ERROR] Native uninstall failed: %v\n%s\n", err, strings.TrimSpace(string(out)))
				fmt.Fprintf(stdout, " Manual cleanup skipped to prevent package database corruption.\n")
				res.Failed++
			} else {
				res.Completed++
				res.PackageUninstallSavings += c.Size
				res.Freed += c.Size
				fmt.Fprintf(stdout, " [UNINSTALLED SUCCESS] %s via '%s'\n", c.Path, execStr)
			}

		case "delete_dir", "delete_file":
			// Quarantine Architecture: Rename candidate to isolated temporary path before inspection & deletion
			nowNano := time.Now().UnixNano()
			quarantinePath := fmt.Sprintf("%s.unslop-quarantine-%d-%d", c.Path, c.ID, nowNano)
			targetPath := c.Path
			opID := fmt.Sprintf("op-%d-%d", c.ID, nowNano)

			entry := QuarantineJournalEntry{
				OpID:           opID,
				OriginalPath:   targetPath,
				QuarantinePath: quarantinePath,
				Phase:          "quarantined",
				Timestamp:      time.Now(),
			}
			_ = recordQuarantineEntry(getJournalPath(), entry)

			if errQ := os.Rename(c.Path, quarantinePath); errQ != nil {
				_ = removeJournalEntry(getJournalPath(), opID)
				fmt.Fprintf(stdout, " [ABORT] Quarantine isolation failed for %s: %v! Action aborted.\n", targetPath, errQ)
				res.Aborted++
				continue
			}

			qInfo, errQStat := os.Lstat(quarantinePath)
			if errQStat != nil || qInfo.IsDir() != c.IsDir {
				fmt.Fprintf(stdout, " [ABORT] Quarantine inspection failed for %s! Rolling back.\n", targetPath)
				if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
					_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
					fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
					res.Failed++
				} else {
					_ = removeJournalEntry(getJournalPath(), opID)
					res.Aborted++
				}
				continue
			}

			// Subtree Revalidation for Directories: Single-pass inspection for size, file count, newest modtime, and protected path checks
			if c.IsDir {
				qSize, qMaxModTime, qFileCount, qHasProt, errQStats := inspectDirectorySubtree(quarantinePath, time.Now())
				if errQStats != nil || qHasProt {
					if qHasProt {
						fmt.Fprintf(stdout, " [PROTECTED SAFEGUARD] Quarantined %s contains protected files! Rolling back.\n", targetPath)
					} else {
						fmt.Fprintf(stdout, " [ABORT] Revalidation traversal failed for quarantined %s: %v! Rolling back.\n", targetPath, errQStats)
					}
					if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
						_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
						fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
						res.Failed++
					} else {
						_ = removeJournalEntry(getJournalPath(), opID)
						res.Aborted++
					}
					continue
				}

				if qFileCount != c.FileCount {
					fmt.Fprintf(stdout, " [ABORT] File count changed for %s (scanned: %d, quarantined: %d)! Rolling back.\n", targetPath, c.FileCount, qFileCount)
					if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
						_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
						fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
						res.Failed++
					} else {
						_ = removeJournalEntry(getJournalPath(), opID)
						res.Aborted++
					}
					continue
				}

				if qSize != c.Size {
					fmt.Fprintf(stdout, " [ABORT] Subtree size changed for %s (scanned: %d B, quarantined: %d B)! Rolling back.\n", targetPath, c.Size, qSize)
					if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
						_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
						fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
						res.Failed++
					} else {
						_ = removeJournalEntry(getJournalPath(), opID)
						res.Aborted++
					}
					continue
				}

				if !c.ModTime.IsZero() && !qMaxModTime.Equal(c.ModTime) {
					fmt.Fprintf(stdout, " [ABORT] Subtree newest modification time changed for %s! Rolling back.\n", targetPath)
					if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
						_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
						fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
						res.Failed++
					} else {
						_ = removeJournalEntry(getJournalPath(), opID)
						res.Aborted++
					}
					continue
				}
			}

			if useTrash {
				_ = updateJournalEntryPhase(getJournalPath(), opID, "deleting")
				if errTrash := moveToTrash(quarantinePath, targetPath); errTrash == nil {
					_ = removeJournalEntry(getJournalPath(), opID)
					res.Completed++
					res.MovedToTrash += c.Size
					fmt.Fprintf(stdout, " [TRASHED] %s\n", targetPath)
				} else {
					fmt.Fprintf(stdout, " [ERROR] Failed to trash %s: %v\n", targetPath, errTrash)
					if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
						_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
						fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
					} else {
						_ = removeJournalEntry(getJournalPath(), opID)
					}
					res.Failed++
				}
			} else {
				if c.IsDir {
					if hasBoundary, _, bErr := containsMountOrReparsePoint(quarantinePath); hasBoundary {
						fmt.Fprintf(stdout, " [REFUSED] Permanent deletion refused for %s: %v! Rolling back.\n", targetPath, bErr)
						if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
							_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
							fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
							res.Failed++
						} else {
							_ = removeJournalEntry(getJournalPath(), opID)
							res.Aborted++
						}
						continue
					}
				}

				_ = updateJournalEntryPhase(getJournalPath(), opID, "deleting")
				var errDel error
				if c.IsDir {
					errDel = os.RemoveAll(quarantinePath)
				} else {
					errDel = os.Remove(quarantinePath)
				}
				if errDel != nil {
					fmt.Fprintf(stdout, " [ERROR] Failed to delete %s: %v\n", targetPath, errDel)
					if c.IsDir {
						_ = updateJournalEntryPhase(getJournalPath(), opID, "partially_deleted")
						fmt.Fprintf(stdout, " [PARTIAL DELETION ERROR] Permanent deletion failed for %s! Tree was partially deleted and cannot be fully rolled back. Remaining contents preserved at %s\n", targetPath, quarantinePath)
					} else {
						if errRB := rollbackQuarantine(targetPath, quarantinePath, stdout); errRB != nil {
							_ = updateJournalEntryPhase(getJournalPath(), opID, "rollback_failed")
							fmt.Fprintf(stdout, " [EMERGENCY ERROR] Rollback failed for %s! Quarantined path preserved at %s: %v\n", targetPath, quarantinePath, errRB)
						} else {
							_ = removeJournalEntry(getJournalPath(), opID)
						}
					}
					res.Failed++
				} else {
					_ = removeJournalEntry(getJournalPath(), opID)
					res.Completed++
					res.FreedPermanently += c.Size
					res.Freed += c.Size
					fmt.Fprintf(stdout, " [DELETED] %s\n", targetPath)
				}
			}
		}
	}

	fmt.Fprintf(stdout, "\n============================================================\n")
	fmt.Fprintf(stdout, " EXECUTION SUMMARY:\n")
	fmt.Fprintf(stdout, "   Attempted: %d | Completed: %d | Skipped: %d | Aborted: %d | Failed: %d\n",
		res.Attempted, res.Completed, res.Skipped, res.Aborted, res.Failed)
	fmt.Fprintf(stdout, "   Permanently Freed:         %s\n", formatBytes(res.FreedPermanently))
	fmt.Fprintf(stdout, "   Moved to Trash:            %s\n", formatBytes(res.MovedToTrash))
	fmt.Fprintf(stdout, "   Package Uninstall Savings: %s\n", formatBytes(res.PackageUninstallSavings))
	fmt.Fprintf(stdout, "============================================================\n")

	return res
}
