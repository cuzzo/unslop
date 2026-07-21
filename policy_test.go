package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompletePolicyMatrixFailClosed(t *testing.T) {
	tests := []struct {
		name              string
		risk              RiskClass
		isDir             bool
		uninstallArgs     []string
		includeData       bool
		containsProtected bool
		expectedAction    string
		expectedCanDelete bool
	}{
		// RiskRegenerable
		{"Regenerable Dir", RiskRegenerable, true, nil, false, false, "delete_dir", true},
		{"Regenerable File", RiskRegenerable, false, nil, false, false, "delete_file", true},
		{"Regenerable Dir With UninstallArgs", RiskRegenerable, true, []string{"npm", "uninstall"}, false, false, "delete_dir", true},
		{"Regenerable Dir Protected", RiskRegenerable, true, nil, false, true, "report-only", false},

		// RiskPackageManaged (All package-managed candidates are report-only in initial alpha for multi-binary safety)
		{"PackageManaged With Uninstaller", RiskPackageManaged, true, []string{"npm", "uninstall"}, false, false, "report-only", false},
		{"PackageManaged No Uninstaller (Custom Category)", RiskPackageManaged, true, nil, false, false, "report-only", false},
		{"PackageManaged File No Uninstaller", RiskPackageManaged, false, nil, false, false, "report-only", false},
		{"PackageManaged Protected", RiskPackageManaged, true, []string{"npm", "uninstall"}, false, true, "report-only", false},

		// RiskUserData
		{"UserData Directory Allowed", RiskUserData, true, nil, true, false, "delete_dir", true},
		{"UserData Directory Refused", RiskUserData, true, nil, false, false, "report-only", false},
		{"UserData File Allowed", RiskUserData, false, nil, true, false, "delete_file", true},
		{"UserData File Refused", RiskUserData, false, nil, false, false, "report-only", false},
		{"UserData Protected", RiskUserData, true, nil, true, true, "report-only", false},

		// RiskUnknown
		{"Unknown Risk Class Dir", RiskUnknown, true, nil, true, false, "report-only", false},
		{"Unknown Risk Class File", RiskUnknown, false, nil, true, false, "report-only", false},

		// Custom / Invalid Risk Class Fallback
		{"Custom Risk Class Fallback", RiskClass("custom_risk"), true, nil, true, false, "report-only", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &Rule{RiskClass: tt.risk, Category: "Test Category"}
			act, canDel := determineCandidateAction(rule, tt.isDir, tt.uninstallArgs, tt.includeData, tt.containsProtected)
			if act != tt.expectedAction {
				t.Errorf("%s: Expected action '%s'; got '%s'", tt.name, tt.expectedAction, act)
			}
			if canDel != tt.expectedCanDelete {
				t.Errorf("%s: Expected canDelete %v; got %v", tt.name, tt.expectedCanDelete, canDel)
			}
		})
	}
}

func TestExecutorRecalculatesPolicyForInconsistentCandidate(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "sample_pkg_file.bin")
	os.WriteFile(sampleFile, []byte("data"), 0644)
	info, _ := os.Lstat(sampleFile)

	// Candidate with inconsistent fields: CanDelete=true and ProposedAction="delete_file", but RiskClass=RiskPackageManaged
	inconsistentCand := Candidate{
		ID:             99,
		Path:           sampleFile,
		Size:           4,
		RiskClass:      RiskPackageManaged,
		Category:       "Package Dependency",
		ProposedAction: "delete_file", // Malformed / inconsistent field
		CanDelete:      true,          // Malformed / inconsistent field
		RootModTime:    info.ModTime(),
		ModTime:        info.ModTime(),
	}

	var stdout bytes.Buffer
	res := confirmAndDeleteWithIO([]Candidate{inconsistentCand}, false, true, false, 1000, 1000, &stdout, strings.NewReader("y\n"))

	out := stdout.String()
	if res.Skipped != 1 || res.Completed != 0 {
		t.Errorf("Expected executor to recalculate policy and refuse action; got skipped=%d, completed=%d\nOutput:\n%s", res.Skipped, res.Completed, out)
	}
	if !strings.Contains(out, "Action refused") && !strings.Contains(out, "report-only") {
		t.Errorf("Expected Action refused message; got:\n%s", out)
	}
}
