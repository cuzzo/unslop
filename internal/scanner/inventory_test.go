package scanner

import (
	"testing"
)

func TestPackageInventoryResolution(t *testing.T) {
	inv := LoadPackageInventory()
	if inv == nil {
		t.Fatalf("Expected non-nil PackageInventory")
	}
}
