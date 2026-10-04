package scanner

import (
	"testing"

	"github.com/yahn/unslop/internal/config"
)

func TestCompletePolicyMatrixFailClosed(t *testing.T) {
	tests := []struct {
		name              string
		risk              config.RiskClass
		includeData       bool
		containsProtected bool
		expectedCanDelete bool
	}{
		{"Regenerable", config.RiskRegenerable, false, false, true},
		{"Regenerable Protected", config.RiskRegenerable, false, true, false},

		{"PackageManaged", config.RiskPackageManaged, false, false, false},
		{"PackageManaged Protected", config.RiskPackageManaged, false, true, false},

		{"UserData Allowed", config.RiskUserData, true, false, true},
		{"UserData Refused", config.RiskUserData, false, false, false},
		{"UserData Protected", config.RiskUserData, true, true, false},

		{"Unknown Risk Class", config.RiskUnknown, true, false, false},

		{"Custom Risk Class Fallback", config.RiskClass("custom_risk"), true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canDel := canDeleteCandidate(tt.risk, tt.includeData, tt.containsProtected)
			if canDel != tt.expectedCanDelete {
				t.Errorf("%s: Expected canDelete %v; got %v", tt.name, tt.expectedCanDelete, canDel)
			}
		})
	}
}
