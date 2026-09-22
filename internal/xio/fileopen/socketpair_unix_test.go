//go:build linux || darwin

package fileopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketpairRejectsInvalidSocktype(t *testing.T) {
	spec, err := parse.ParseSpec("SOCKETPAIR,so-type=99")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error=%v", err)
	}
}
