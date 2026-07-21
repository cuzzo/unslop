package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
