package format

import (
	"path/filepath"
	"testing"
)

func TestAbbreviateHomePath(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if got := AbbreviateHomePath(tmpHome); got != "~" {
		t.Errorf("Expected '~' for home dir; got '%s'", got)
	}

	subFile := filepath.Join(tmpHome, "projects", "my-app")
	expected := filepath.Join("~", "projects", "my-app")
	if got := AbbreviateHomePath(subFile); got != expected {
		t.Errorf("Expected '%s' for subpath; got '%s'", expected, got)
	}

	otherPath := "/var/log/system.log"
	if got := AbbreviateHomePath(otherPath); got != otherPath {
		t.Errorf("Expected non-home path to remain '%s'; got '%s'", otherPath, got)
	}
}

func TestFormatAgeDays(t *testing.T) {
	tests := []struct {
		days     float64
		expected string
	}{
		{14.2, " 14.2d"},
		{99.9, " 99.9d"},
		{100.0, "  100d"},
		{142.2, "  142d"},
		{1000.0, " 1000d"},
	}

	for _, tt := range tests {
		got := FormatAgeDays(tt.days)
		if got != tt.expected {
			t.Errorf("FormatAgeDays(%f) = %q; want %q", tt.days, got, tt.expected)
		}
	}
}
