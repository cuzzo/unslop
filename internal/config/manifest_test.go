package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOverridesRemoveMatchingRulesAndPreserveOtherRules(t *testing.T) {
	engine := NewRuleEngine(Manifest{Rules: []Rule{
		{ID: "cache", Target: "any", Patterns: []string{"*.cache", "artifact"}, RiskClass: RiskRegenerable},
		{ID: "sessions", Target: "dir", Patterns: []string{"sessions"}, RiskClass: RiskUserData},
	}})
	removed, added := ApplyRuleOverrides(engine, []string{"-*.cache", "+custom"})
	if len(removed) != 1 || removed[0] != "cache" || len(added) != 1 || added[0] != "custom" || len(engine.Rules) != 2 {
		t.Fatalf("overrides changed unrelated rules: removed=%v added=%v rules=%+v", removed, added, engine.Rules)
	}
	if engine.Match("artifact", "artifact", false) != nil || engine.Match("sessions", "sessions", true) == nil {
		t.Fatal("override failed to remove the whole matching rule or lost the protected rule")
	}
	if rule := engine.Match("custom", "custom", false); rule == nil || rule.RiskClass != RiskUnknown {
		t.Fatalf("custom override escaped unknown-risk policy: %+v", rule)
	}
}

func TestMatchKeepsDirectoryMarkerAndFileRules(t *testing.T) {
	for _, tc := range []struct {
		isDir, parentMarker, internalMarker bool
		want                                string
	}{
		{true, false, false, "fallback"},
		{true, true, false, "fallback"},
		{true, false, true, "fallback"},
		{true, true, true, "marked"},
		{false, false, false, "marked"},
	} {
		parent := t.TempDir()
		path := filepath.Join(parent, "cache")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		for name, present := range map[string]bool{filepath.Join(parent, "project"): tc.parentMarker, filepath.Join(path, "index"): tc.internalMarker} {
			if present {
				if err := os.WriteFile(name, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		engine := NewRuleEngine(Manifest{Rules: []Rule{
			{ID: "marked", Target: "any", Patterns: []string{"cache"}, MarkerFiles: []string{"missing", "project"}, InternalMarkerFiles: []string{"index"}},
			{ID: "fallback", Target: "dir", Patterns: []string{"cache"}},
		}})
		if rule := engine.Match("cache", path, tc.isDir); rule == nil || rule.ID != tc.want {
			t.Fatalf("case=%+v rule=%+v", tc, rule)
		}
	}
}

func TestPathRulesMatchAbsolutePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{".codex/cache", filepath.Join(home, ".codex/cache"), true},
		{"Library/Application Support/Code/logs", filepath.Join(home, "Library/Application Support/Code/logs"), true},
		{"node_modules/.cache", filepath.Join(home, "dev/project/node_modules/.cache"), true},
		{"*/.cargo/bin/*", filepath.Join(home, ".cargo/bin/tool"), true},
		{"~/Library/Caches/Homebrew", filepath.Join(home, "Library/Caches/Homebrew"), true},
		{"~/Library/Caches/Homebrew", filepath.Join(home, "project/Library/Caches/Homebrew"), false},
		{filepath.Join(home, "cache"), filepath.Join(home, "other/cache"), false},
		{"missing/cache", filepath.Join(home, "other/cache"), false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			engine := NewRuleEngine(Manifest{Rules: []Rule{{ID: "test", Target: "any", Patterns: []string{tc.pattern}}}})
			dir := engine.Match(filepath.Base(tc.path), tc.path, true)
			file := engine.Match(filepath.Base(tc.path), tc.path, false)
			if (dir != nil) != tc.want || (file != nil) != tc.want {
				t.Fatalf("dir=%v file=%v want match=%v", dir, file, tc.want)
			}
		})
	}
}

func TestHomePatternFailsWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	engine := NewRuleEngine(Manifest{Rules: []Rule{{ID: "test", Target: "dir", Patterns: []string{"~/.codex/cache"}}}})
	if rule := engine.Match("cache", "/.codex/cache", true); rule != nil {
		t.Fatal("matched without home directory")
	}
}

func TestDefaultMacAndSessionRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	m, err := LoadManifest("")
	if err != nil {
		t.Fatal(err)
	}
	engine := NewRuleEngine(m)
	for _, tc := range []struct {
		path, id string
		risk     RiskClass
	}{
		{"Applications/Example.app/Contents/Frameworks/library.dylib", "dev_binaries", RiskUnknown},
		{"Library/Developer/Xcode/DerivedData", "xcode_derived_data", RiskRegenerable},
		{"Library/Caches/Homebrew", "homebrew_cache", RiskPackageManaged},
		{".pi/agent/sessions/project/session.jsonl", "pi_sessions", RiskUserData},
		{".gemini/antigravity-cli/brain/session", "antigravity_sessions", RiskUserData},
		{".gemini/antigravity/brain/session", "antigravity_sessions", RiskUserData},
		{".gemini/antigravity-ide/conversations", "antigravity_sessions", RiskUserData},
		{".gemini/antigravity-cli/implicit", "antigravity_memory", RiskUserData},
		{".cache/huggingface/hub", "llm_models", RiskUserData},
	} {
		t.Run(tc.path, func(t *testing.T) {
			p := filepath.Join(home, tc.path)
			var rule *Rule
			if filepath.Ext(p) != "" {
				rule = engine.Match(filepath.Base(p), p, false)
			} else {
				rule = engine.Match(filepath.Base(p), p, true)
			}
			if rule == nil || rule.ID != tc.id || rule.RiskClass != tc.risk {
				t.Fatalf("got %+v, want %s/%s", rule, tc.id, tc.risk)
			}
		})
	}
	for _, dir := range []string{".cache/huggingface", ".cache/arbitrary"} {
		p := filepath.Join(home, dir)
		if rule := engine.Match(filepath.Base(p), p, true); rule != nil {
			t.Fatalf("unclassified cache matched %+v", rule)
		}
	}
	rootManifest, err := os.ReadFile("../../manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootManifest, defaultManifestData) {
		t.Fatal("root and embedded manifests differ")
	}
}

func TestManifestMigrationLegacyToV1(t *testing.T) {
	legacyJSON := `{
		"rules": [
			{"id": "legacy_rule_1", "name": "Legacy 1", "target": "dir", "patterns": [".cargo"], "category": "UNUSED (Cargo)"},
			{"id": "legacy_rule_2", "name": "Legacy 2", "target": "dir", "patterns": ["tmp-*"], "category": "Cache Dir"}
		]
	}`

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	manifestPath := filepath.Join(tmpHome, ".unslop.json")
	if err := os.WriteFile(manifestPath, []byte(legacyJSON), 0644); err != nil {
		t.Fatalf("Failed to write legacy manifest: %v", err)
	}

	m, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("Failed to load and migrate legacy manifest: %v", err)
	}

	if m.Version != 1 {
		t.Errorf("Expected manifest Version to be migrated to 1; got %d", m.Version)
	}

	for _, r := range m.Rules {
		if r.RiskClass != RiskUnknown {
			t.Errorf("Expected missing risk_class in legacy rule '%s' to migrate to RiskUnknown; got %s", r.ID, r.RiskClass)
		}
	}
}

func TestManifestValidationErrors(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name: "Unsupported Version",
			json: `{
				"version": 2,
				"rules": [{"id": "r1", "name": "R1", "target": "dir", "patterns": ["p1"], "risk_class": "regenerable"}]
			}`,
			wantErr: true,
		},
		{
			name: "Invalid Risk Class",
			json: `{
				"rules": [{"id": "r1", "name": "R1", "target": "dir", "patterns": ["p1"], "risk_class": "invalid_risk"}]
			}`,
			wantErr: true,
		},
		{
			name: "Empty Rule ID",
			json: `{
				"rules": [{"id": "", "name": "R1", "target": "dir", "patterns": ["p1"], "risk_class": "regenerable"}]
			}`,
			wantErr: true,
		},
		{
			name: "Duplicate Rule ID",
			json: `{
				"rules": [
					{"id": "r1", "name": "R1", "target": "dir", "patterns": ["p1"], "risk_class": "regenerable"},
					{"id": "r1", "name": "R2", "target": "file", "patterns": ["p2"], "risk_class": "regenerable"}
				]
			}`,
			wantErr: true,
		},
		{
			name: "Invalid Target",
			json: `{
				"rules": [{"id": "r1", "name": "R1", "target": "invalid_target", "patterns": ["p1"], "risk_class": "regenerable"}]
			}`,
			wantErr: true,
		},
		{
			name: "Empty Patterns List",
			json: `{
				"rules": [{"id": "r1", "name": "R1", "target": "dir", "patterns": [], "risk_class": "regenerable"}]
			}`,
			wantErr: true,
		},
		{
			name: "Empty Pattern String",
			json: `{
				"rules": [{"id": "r1", "name": "R1", "target": "dir", "patterns": ["  "], "risk_class": "regenerable"}]
			}`,
			wantErr: true,
		},
		{
			name: "Valid Manifest With Rule Conflict Warning",
			json: `{
				"version": 1,
				"rules": [
					{"id": "r1", "name": "R1", "target": "dir", "patterns": ["shared_pat"], "risk_class": "regenerable"},
					{"id": "r2", "name": "R2", "target": "dir", "patterns": ["shared_pat"], "risk_class": "regenerable"}
				]
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(tmpDir, "manifest_"+tt.name+".json")
			os.WriteFile(p, []byte(tt.json), 0644)
			_, err := LoadManifest(p)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: LoadManifest() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}
