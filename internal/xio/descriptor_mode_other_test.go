//go:build !windows

package xio

import (
	"strings"
	"testing"
)

func TestDescriptorModesRejectOffWindows(t *testing.T) {
	for _, raw := range []string{
		"FD:3,binary", "FD:3,binary=0", "FD:3,text", "FD:3,noinherit", "FD:3,o-noinherit=0",
	} {
		err := ValidateDescriptorModeOptions(mustSpec(t, raw))
		if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
			t.Errorf("%s: error=%v", raw, err)
		}
	}
}
