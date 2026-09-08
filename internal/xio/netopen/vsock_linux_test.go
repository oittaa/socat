//go:build linux

package netopen

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func skipIfNoVSOCK(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("no AF_VSOCK: %v", err)
	}
	_ = unix.Close(fd)
}

func skipIfNoVSOCKListen(t *testing.T) net.Listener {
	t.Helper()
	skipIfNoVSOCK(t)
	ln, err := listenVSOCK(context.Background(), vsockPortAny, parse.Spec{}, nil)
	if err != nil {
		t.Skipf("VSOCK-LISTEN: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestVSOCKListenAcceptTimeout(t *testing.T) {
	skipIfNoVSOCK(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("VSOCK-LISTEN:-1,accept-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	_, err = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
	if err != nil && vsockLoopbackUnavailable(err) {
		t.Skip(err.Error())
	}
	if err != xio.ErrAcceptTimeout {
		t.Fatalf("want accept timeout, got %v", err)
	}
}

func TestVSOCKListenAddrPortAssigned(t *testing.T) {
	ln := skipIfNoVSOCKListen(t)
	addr, ok := ln.Addr().(*vsockAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	if addr.Port == 0 || addr.Port == vsockPortAny {
		t.Fatalf("expected kernel-assigned port, got %d", addr.Port)
	}
	if addr.CID != unix.VMADDR_CID_ANY {
		t.Fatalf("listen cid=%d want ANY", addr.CID)
	}
}

func vsockLoopbackUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case unix.ENODEV, unix.EADDRNOTAVAIL, unix.ENETUNREACH, unix.EOPNOTSUPP, unix.EACCES, unix.EPERM:
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "No such device") ||
		strings.Contains(msg, "cannot assign requested address") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "permission denied")
}

func TestVSOCKListenPortZeroDenied(t *testing.T) {
	skipIfNoVSOCK(t)
	_, err := listenVSOCK(context.Background(), 0, parse.Spec{}, nil)
	if err == nil {
		t.Fatal("VSOCK-LISTEN:0 succeeded; classic bind of port 0 is EACCES")
	}
	if !errors.Is(err, unix.EACCES) && !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err=%v want permission denied", err)
	}
}

func TestVSOCKListenPFInetAddressFamily(t *testing.T) {
	skipIfNoVSOCK(t)
	s, err := parse.ParseSpec("VSOCK-LISTEN:9,pf=inet")
	if err != nil {
		t.Fatal(err)
	}
	_, err = listenVSOCK(context.Background(), 9, s, nil)
	if err == nil {
		t.Fatal("pf=inet succeeded; classic bind is EAFNOSUPPORT")
	}
	if !errors.Is(err, unix.EAFNOSUPPORT) && !strings.Contains(err.Error(), "address family") {
		t.Fatalf("err=%v want address family not supported", err)
	}
}

func TestVSOCKListenProtocolAliases(t *testing.T) {
	skipIfNoVSOCK(t)
	for _, name := range []string{"so-protocol", "protocol"} {
		t.Run(name, func(t *testing.T) {
			s, err := parse.ParseSpec("VSOCK-LISTEN:9," + name + "=6")
			if err != nil {
				t.Fatal(err)
			}
			_, err = listenVSOCK(context.Background(), 9, s, nil)
			if err == nil {
				t.Fatalf("%s=6 succeeded; classic socket() is EPROTONOSUPPORT", name)
			}
			if !errors.Is(err, unix.EPROTONOSUPPORT) && !strings.Contains(err.Error(), "protocol not supported") {
				t.Fatalf("err=%v want protocol not supported", err)
			}
		})
	}
}
