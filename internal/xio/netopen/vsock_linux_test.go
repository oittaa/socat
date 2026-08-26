//go:build linux

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
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
	ln, err := listenVSOCK(context.Background(), 0, parse.Spec{}, nil)
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
	ch, err := parse.ParseChannel("VSOCK-LISTEN:0,accept-timeout=0.05")
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

func TestVSOCKEchoLoopback(t *testing.T) {
	ln := skipIfNoVSOCKListen(t)
	addr, ok := ln.Addr().(*vsockAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- "accept:" + err.Error()
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 10)
		n, err := io.ReadFull(c, b)
		if err != nil {
			got <- "read:" + err.Error()
			return
		}
		got <- string(b[:n])
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	g := &xio.Global{Log: logx.New()}
	c, err := dialVSOCK(ctx, vsockEndpoint{cid: unix.VMADDR_CID_LOCAL, port: addr.Port}, parse.Spec{}, g, 250*time.Millisecond, nil)
	if err != nil {
		if vsockLoopbackUnavailable(err) {
			t.Skipf("VSOCK loopback not available: %v", err)
		}
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "hellovsock"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatal("timeout")
	case s := <-got:
		if s != "hellovsock" {
			t.Fatalf("got %q", s)
		}
	}
}

func TestVSOCKOpenChannelEcho(t *testing.T) {
	skipIfNoVSOCK(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	g := useGlobal()
	lo, err := xio.OpenChannel(ctx, parseChannel(t, "VSOCK-LISTEN:0,fork"), xio.ModeRDWR, g)
	if err != nil {
		if vsockLoopbackUnavailable(err) {
			t.Skip(err.Error())
		}
		t.Fatal(err)
	}
	if lo.Listener == nil {
		_ = lo.Close()
		t.Fatal("VSOCK-LISTEN did not return a listener")
	}
	go func() { _ = xio.RunOpened(ctx, lo, parseChannel(t, "PIPE"), g) }()
	addr, ok := lo.Listener.Addr().(*vsockAddr)
	if !ok {
		t.Fatalf("addr type %T", lo.Listener.Addr())
	}
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "VSOCK-CONNECT:1:"+strconv.FormatUint(uint64(addr.Port), 10)+",connect-timeout=0.25"), xio.ModeRDWR, useGlobal())
	if err != nil {
		if vsockLoopbackUnavailable(err) {
			t.Skip(err.Error())
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("vsock-use"))
}

func TestVSOCKRememberAddrs(t *testing.T) {
	ln := skipIfNoVSOCKListen(t)
	addr := ln.Addr().(*vsockAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	g := &xio.Global{Log: logx.New()}
	c, err := dialVSOCK(ctx, vsockEndpoint{cid: unix.VMADDR_CID_LOCAL, port: addr.Port}, parse.Spec{}, g, 250*time.Millisecond, nil)
	if err != nil {
		if vsockLoopbackUnavailable(err) {
			t.Skipf("VSOCK loopback not available: %v", err)
		}
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	xio.RememberAddrs(g, c)
	if g.PeerAddr == "" || g.PeerPort == "" {
		t.Fatalf("peer addr=%q port=%q", g.PeerAddr, g.PeerPort)
	}
	if g.PeerPort != strconv.FormatUint(uint64(addr.Port), 10) {
		t.Fatalf("PEERPORT=%q want %d", g.PeerPort, addr.Port)
	}
	select {
	case ac := <-accepted:
		if ac != nil {
			_ = ac.Close()
		}
	case <-ctx.Done():
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
