//go:build linux || darwin

package fileopen

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketpairRejectsInvalidSocktype(t *testing.T) {
	_, err := openSocketpair(context.Background(), mustAddr(t, parse.Spec{
		Type:    "SOCKETPAIR",
		Options: []parse.Option{{Name: "socktype", Value: "99", Has: true}},
	}), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error=%v", err)
	}
}
