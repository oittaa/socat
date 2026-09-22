//go:build linux || darwin

package fileopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketpairRejectsInvalidSocktype(t *testing.T) {
	_, err := xio.PrepareSpec(parse.Spec{
		Type:    "SOCKETPAIR",
		Options: []parse.Option{{Name: "socktype", Value: "99", Has: true}},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error=%v", err)
	}
}
