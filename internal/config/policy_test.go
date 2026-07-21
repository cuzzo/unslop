package config

import (
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
