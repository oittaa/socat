//go:build windows

package netopen

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestWindowsUnixConnectMissingPathKeepsDialError(t *testing.T) {
	path := testutil.UnixSocketPath(t, "missing.sock")
	spec := parse.Spec{Type: "UNIX-CONNECT", Params: []string{path}}
	_, err := openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	op, ok := err.(*net.OpError)
	if !ok || !strings.Contains(err.Error(), path) {
		t.Fatalf("error=%T %v", err, err)
	}
	if op.Op != "dial" {
		t.Fatalf("op=%q error=%v", op.Op, err)
	}
}

func TestWindowsUnixConnectBindFailureNamesBindPath(t *testing.T) {
	dest := testutil.UnixSocketPath(t, "dest.sock")
	bindPath := testutil.UnixSocketPath(t, "bind.sock")
	startWindowsUnixStreamPeer(t, dest)
	startWindowsUnixStreamPeer(t, bindPath)
	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{dest},
		Options: []parse.Option{{Name: "bind", Value: bindPath, Has: true}},
	}
	_, err := openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	op, ok := err.(*net.OpError)
	if !ok || op.Err == nil || !strings.Contains(op.Err.Error(), "bind") || !strings.Contains(op.Err.Error(), bindPath) {
		t.Fatalf("error=%T %v", err, err)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("error=%v want EADDRINUSE", err)
	}
}
