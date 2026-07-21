package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed manifest.json
var defaultManifestData []byte

const Version = "0.2.0-alpha"

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

type Rule struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Target              string    `json:"target"` // "dir", "file", "any"
	Patterns            []string  `json:"patterns"`
	Category            string    `json:"category"`
	MarkerFiles         []string  `json:"marker_files,omitempty"`
	InternalMarkerFiles []string  `json:"internal_marker_files,omitempty"`
	CheckUnusedAtime    bool      `json:"check_unused_atime,omitempty"`
	RiskClass           RiskClass `json:"risk_class"`
	MinSizeMB           float64   `json:"min_size_mb,omitempty"`
}

type Manifest struct {
	Version           int     `json:"version,omitempty"`
	DefaultDays       float64 `json:"default_days"`
	DefaultMinSizeMB float64 `json:"default_min_size_mb"`
	Rules             []Rule  `json:"rules"`
}

type RuleEngine struct {
	Rules []Rule
}

func NewRuleEngine(m Manifest) *RuleEngine {
	return &RuleEngine{Rules: m.Rules}
}

func matchGlob(pattern, name string) bool {
	if pattern == name {
		return true
	}
	matched, err := filepath.Match(pattern, name)
	if err == nil && matched {
		return true
	}
	return false
}

func hasMarkerFile(dirPath string, markerFiles []string) bool {
	if len(markerFiles) == 0 {
		return true
	}
	parent := filepath.Dir(dirPath)
	for _, mf := range markerFiles {
		mfPath := filepath.Join(parent, mf)
		if _, err := os.Lstat(mfPath); err == nil {
			return true
		}
	}
	return false
}

func hasInternalMarkerFile(dirPath string, internalMarkerFiles []string) bool {
	if len(internalMarkerFiles) == 0 {
		return true
	}
	for _, imf := range internalMarkerFiles {
		imfPath := filepath.Join(dirPath, imf)
		if _, err := os.Lstat(imfPath); err == nil {
			return true
		}
	}
	return false
}

func (e *RuleEngine) MatchDir(dirName, fullPath string, pkgInventory map[string]string) (*Rule, string, []string) {
	for _, rule := range e.Rules {
		if rule.Target != "dir" && rule.Target != "any" {
			continue
		}
		for _, pat := range rule.Patterns {
			if strings.Contains(pat, "/") {
				if matchGlob(pat, fullPath) {
					if hasMarkerFile(fullPath, rule.MarkerFiles) && hasInternalMarkerFile(fullPath, rule.InternalMarkerFiles) {
						rCopy := rule
						return &rCopy, "", nil
					}
				}
			} else {
				if matchGlob(pat, dirName) {
					if hasMarkerFile(fullPath, rule.MarkerFiles) && hasInternalMarkerFile(fullPath, rule.InternalMarkerFiles) {
						rCopy := rule
						return &rCopy, "", nil
					}
				}
			}
		}
	}
	return nil, "", nil
}

func (e *RuleEngine) MatchFile(fileName, fullPath string, fi os.FileInfo, pkgInventory map[string]string) (*Rule, string, []string) {
	for _, rule := range e.Rules {
		if rule.Target != "file" && rule.Target != "any" {
			continue
		}
		for _, pat := range rule.Patterns {
			if strings.Contains(pat, "/") {
				if matchGlob(pat, fullPath) {
					rCopy := rule
					return &rCopy, "", nil
				}
			} else {
				if matchGlob(pat, fileName) {
					rCopy := rule
					return &rCopy, "", nil
				}
			}
		}
	}
	return nil, "", nil
}

func shouldWarnConflict(r1, r2 Rule) bool {
	if len(r1.MarkerFiles) == 0 && len(r2.MarkerFiles) == 0 && len(r1.InternalMarkerFiles) == 0 && len(r2.InternalMarkerFiles) == 0 {
		return true
	}
	for _, m1 := range r1.MarkerFiles {
		for _, m2 := range r2.MarkerFiles {
			if strings.EqualFold(m1, m2) {
				return true
			}
		}
	}
	for _, m1 := range r1.InternalMarkerFiles {
		for _, m2 := range r2.InternalMarkerFiles {
			if strings.EqualFold(m1, m2) {
				return true
			}
		}
	}
	return false
}

func validateManifest(m Manifest) error {
	if m.Version > 1 {
		return fmt.Errorf("unsupported manifest version %d (supported max version: 1)", m.Version)
	}

	seenIDs := make(map[string]bool)
	seenPatterns := make(map[string]string)
	existingRuleByID := make(map[string]Rule)

	for _, r := range m.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("manifest rule contains empty 'id'")
		}
		if seenIDs[r.ID] {
			return fmt.Errorf("duplicate rule ID '%s' found in manifest", r.ID)
		}
		seenIDs[r.ID] = true
		existingRuleByID[r.ID] = r

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
			if existingRuleID, exists := seenPatterns[key]; exists {
				existingRule := existingRuleByID[existingRuleID]
				if shouldWarnConflict(r, existingRule) {
					fmt.Fprintf(os.Stderr, "[MANIFEST WARNING] Rule '%s' pattern '%s' (target: %s) conflicts with rule '%s'.\n", r.ID, pat, r.Target, existingRuleID)
				}
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

func LoadManifest(customPath string) (Manifest, error) {
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

func CalculateDynamicMinSizeMB(diskTotalBytes uint64) float64 {
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

	scaledMB := diskGB * 0.05
	if scaledMB < minFloorMB {
		return minFloorMB
	}
	if scaledMB > maxCapMB {
		return maxCapMB
	}
	return scaledMB
}

func ApplyRuleOverrides(engine *RuleEngine, args []string) ([]string, []string) {
	var removed []string
	var added []string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			pat := strings.TrimPrefix(arg, "-")
			var filtered []Rule
			for _, r := range engine.Rules {
				matched := false
				for _, p := range r.Patterns {
					if p == pat || matchGlob(pat, p) {
						matched = true
						break
					}
				}
				if matched {
					removed = append(removed, r.ID)
				} else {
					filtered = append(filtered, r)
				}
			}
			engine.Rules = filtered
		} else if strings.HasPrefix(arg, "+") && len(arg) > 1 {
			pat := strings.TrimPrefix(arg, "+")
			customRule := Rule{
				ID:        "custom_" + fmt.Sprintf("%d", time.Now().UnixNano()),
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
