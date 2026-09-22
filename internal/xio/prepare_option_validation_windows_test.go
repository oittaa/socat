//go:build windows

package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestPrepareUserGroupUnsupportedOnWindows(t *testing.T) {
	for _, raw := range []string{
		"CREATE:/tmp/socat-owner-hex,user=0x10,group=0x20",
		"CREATE:/tmp/socat-owner-num,user=65534",
		"CREATE:/tmp/socat-owner-num,group=65534",
	} {
		_, err := xio.PrepareSpec(mustParseSpec(t, raw))
		if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}
