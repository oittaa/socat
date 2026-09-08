//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestOpenSpecRejectsTCPRecvAncillary(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:127.0.0.1:1,ip-pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, useGlobal())
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err=%v want not supported", err)
	}
}

func skipIfRawIPPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("SOCK_RAW requires CAP_NET_RAW: %v", err)
	}
}

func TestOpenSpecRejectsTCPHdrincl(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:127.0.0.1:1,ip-hdrincl")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, useGlobal())
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err=%v want not supported", err)
	}
}
