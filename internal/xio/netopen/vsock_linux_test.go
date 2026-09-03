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

func parseVSOCKAddr(t *testing.T, a net.Addr) (cid, port uint32) {
	t.Helper()
	if a == nil || a.Network() != "vsock" {
		t.Fatalf("addr network=%v want vsock", a)
	}
	parts := strings.Split(a.String(), ":")
	if len(parts) != 2 {
		t.Fatalf("addr string=%q want cid:port", a.String())
	}
	c, err1 := strconv.ParseUint(parts[0], 10, 32)
	p, err2 := strconv.ParseUint(parts[1], 10, 32)
	if err1 != nil || err2 != nil {
		t.Fatalf("parse vsock addr %q: %v, %v", a.String(), err1, err2)
	}
	return uint32(c), uint32(p)
}

func TestVSOCKListenAddrPortAssigned(t *testing.T) {
	ln := skipIfNoVSOCKListen(t)
	cid, port := parseVSOCKAddr(t, ln.Addr())
	if port == 0 || port == vsockPortAny {
		t.Fatalf("expected kernel-assigned port, got %d", port)
	}
	if cid != unix.VMADDR_CID_ANY {
		t.Fatalf("listen cid=%d want ANY", cid)
	}
}

func TestVSOCKEchoLoopback(t *testing.T) {
	ln := skipIfNoVSOCKListen(t)
	_, port := parseVSOCKAddr(t, ln.Addr())
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
	c, err := dialVSOCK(ctx, vsockEndpoint{cid: unix.VMADDR_CID_LOCAL, port: port}, parse.Spec{}, g, 250*time.Millisecond, nil)
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
	lo, err := xio.OpenChannel(ctx, parseChannel(t, "VSOCK-LISTEN:-1,fork"), xio.ModeRDWR, g)
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
	_, port := parseVSOCKAddr(t, lo.Listener.Addr())
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "VSOCK-CONNECT:1:"+strconv.FormatUint(uint64(port), 10)+",connect-timeout=0.25"), xio.ModeRDWR, useGlobal())
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
	_, port := parseVSOCKAddr(t, ln.Addr())
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
	c, err := dialVSOCK(ctx, vsockEndpoint{cid: unix.VMADDR_CID_LOCAL, port: port}, parse.Spec{}, g, 250*time.Millisecond, nil)
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
	if g.PeerPort != strconv.FormatUint(uint64(port), 10) {
		t.Fatalf("PEERPORT=%q want %d", g.PeerPort, port)
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

func TestVSOCKDialWrapperSupportsDeadlines(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[1]) }()

	c, err := newVsockConn(fds[0], &vsockAddr{}, &vsockAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.SetDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatalf("connected wrapper does not support deadlines: %v", err)
	}
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("blocking socketpair read succeeded; expected deadline")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, unix.EAGAIN) && !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("read error %v, want deadline", err)
	}
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

func TestVSOCKListenSocktypeAliasesRaw(t *testing.T) {
	skipIfNoVSOCK(t)
	for _, name := range []string{"so-type", "type"} {
		t.Run(name, func(t *testing.T) {
			s, err := parse.ParseSpec("VSOCK-LISTEN:9," + name + "=3")
			if err != nil {
				t.Fatal(err)
			}
			_, err = listenVSOCK(context.Background(), 9, s, nil)
			if err == nil {
				t.Fatalf("%s=3 succeeded; classic socket() is ESOCKTNOSUPPORT", name)
			}
			if strings.Contains(err.Error(), "unsupported socktype") {
				t.Fatalf("%s=3 rejected in user space: %v", name, err)
			}
			if !errors.Is(err, unix.ESOCKTNOSUPPORT) && !errors.Is(err, unix.EPROTONOSUPPORT) && !strings.Contains(err.Error(), "socket type") {
				t.Fatalf("err=%v want socket type not supported", err)
			}
		})
	}
}
