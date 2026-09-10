//go:build darwin || windows

package xio

import "testing"

func TestFeatureNAMESPACESOff(t *testing.T) {
	if FeatureNAMESPACES {
		t.Fatal("WITH_NAMESPACES must be off outside Linux")
	}
}
