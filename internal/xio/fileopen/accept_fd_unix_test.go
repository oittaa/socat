//go:build unix

package fileopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func dupOwnedFD(t *testing.T, fd int) int {
	t.Helper()
	nfd, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(nfd)
	return nfd
}

func tcp4ListenOwned(t *testing.T) (fd int, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpln, ok := ln.(*net.TCPListener)
	if !ok {
		_ = ln.Close()
		t.Fatalf("listener %T", ln)
	}
	f, err := tcpln.File()
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()
	fd = dupOwnedFD(t, int(f.Fd()))
	_ = f.Close()
	return fd, addr
}

func parseAcceptSpec(t *testing.T, spec string, fd int) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	s.Params = []string{strconv.Itoa(fd)}
	return s
}

func readStream(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		return buf
	case <-time.After(4 * time.Second):
		t.Fatal("timed out reading")
		return nil
	}
}

func TestAcceptFDTransfersAndSetsEnv(t *testing.T) {
	fd, addr := tcp4ListenOwned(t)
	g := &xio.Global{}
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := openAcceptFD(context.Background(), parseAcceptSpec(t, "ACCEPT-FD:0", fd), xio.ModeRDWR, g)
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()

	cli, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	var o *xio.Opened
	select {
	case o = <-opened:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(4 * time.Second):
		t.Fatal("ACCEPT-FD accept timed out")
	}
	t.Cleanup(func() { _ = o.Close() })

	payload := []byte("accept-fd-hello")
	if _, err := cli.Write(payload); err != nil {
		t.Fatal(err)
	}
	if got := readStream(t, o.Stream, len(payload)); string(got) != string(payload) {
		t.Fatalf("read %q want %q", got, payload)
	}
	if _, err := o.Stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo %q want %q", got, payload)
	}

	if g.SockAddr == "" || g.SockPort == "" {
		t.Fatalf("SOCKADDR/SOCKPORT empty: %q %q", g.SockAddr, g.SockPort)
	}
	if g.PeerAddr == "" || g.PeerPort == "" {
		t.Fatalf("PEERADDR/PEERPORT empty: %q %q", g.PeerAddr, g.PeerPort)
	}
	if g.SockAddr != "127.0.0.1" {
		t.Fatalf("SOCKADDR=%q want 127.0.0.1", g.SockAddr)
	}
	if g.PeerAddr != "127.0.0.1" {
		t.Fatalf("PEERADDR=%q want 127.0.0.1", g.PeerAddr)
	}
}

func TestAcceptAliasOpensSameAsAcceptFD(t *testing.T) {
	fd, addr := tcp4ListenOwned(t)
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := openAcceptFD(context.Background(), parseAcceptSpec(t, "ACCEPT:0", fd), xio.ModeRDWR, nil)
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()
	cli, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	select {
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		if _, err := cli.Write([]byte("alias")); err != nil {
			t.Fatal(err)
		}
		if got := readStream(t, o.Stream, 5); string(got) != "alias" {
			t.Fatalf("got %q", got)
		}
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(4 * time.Second):
		t.Fatal("ACCEPT alias timed out")
	}
}

func TestAcceptFDHexFdNumber(t *testing.T) {
	fd, addr := tcp4ListenOwned(t)
	s, err := parse.ParseSpec("ACCEPT-FD:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Params = []string{fmt.Sprintf("0x%x", fd)}
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := openAcceptFD(context.Background(), s, xio.ModeRDWR, nil)
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()
	cli, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	select {
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(4 * time.Second):
		t.Fatal("hex fd accept timed out")
	}
}

func TestAcceptFDRejectedPeerKeepsListenFD(t *testing.T) {
	fd, addr := tcp4ListenOwned(t)
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		s := parseAcceptSpec(t, "ACCEPT-FD:0,range=127.0.0.2/32", fd)
		o, err := openAcceptFD(context.Background(), s, xio.ModeRDWR, nil)
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()

	denied, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = denied.Write([]byte("nope"))
	_ = denied.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, rerr := denied.Read(buf)
	_ = denied.Close()
	if n > 0 {
		t.Fatalf("range-rejected peer read %q", buf[:n])
	}
	if rerr == nil {
		t.Fatal("range-rejected peer: expected EOF or error")
	}

	// Listen fd must still accept. 127.0.0.2 is typically on lo (127.0.0.0/8).
	d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	okConn, err := d.Dial("tcp4", addr)
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2 as source (%v); listen stayed up through the refused peer", err)
	}
	t.Cleanup(func() { _ = okConn.Close() })

	select {
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		if _, err := okConn.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		if got := readStream(t, o.Stream, 2); string(got) != "ok" {
			t.Fatalf("got %q", got)
		}
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(4 * time.Second):
		t.Fatal("permitted peer was not accepted")
	}
}

func TestAcceptFDRejectedPeer10Net(t *testing.T) {
	fd, addr := tcp4ListenOwned(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		s := parseAcceptSpec(t, "ACCEPT-FD:0,range=10.0.0.0/8", fd)
		_, err := openAcceptFD(ctx, s, xio.ModeRDWR, nil)
		errCh <- err
	}()

	c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("nope"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, rerr := c.Read(buf)
	_ = c.Close()
	if n > 0 {
		t.Fatalf("range-rejected peer read %q", buf[:n])
	}
	if rerr == nil {
		t.Fatal("range-rejected peer: expected EOF or error")
	}

	c2, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("second dial after refuse: %v; listen fd should stay open", err)
	}
	_ = c2.Close()
	cancel()
}

func TestAcceptFDCloseDoesNotDoubleClose(t *testing.T) {
	fd, _ := tcp4ListenOwned(t)
	// fork returns before accept so we can inspect the listen fd without an
	// accepted conn reusing the original number.
	o, err := openAcceptFD(context.Background(), parseAcceptSpec(t, "ACCEPT-FD:0,fork", fd), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
		t.Fatal("original listen fd still open after FileListener wrap")
	}
	newfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(newfd) })
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(newfd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("Opened.Close closed recycled descriptor old=%d new=%d: %v", fd, newfd, err)
	}
}

func TestAcceptFDRejectsPipeUDPAndConnected(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	pipeFD := dupOwnedFD(t, int(r.Fd()))
	_, err = openAcceptFD(context.Background(), parseAcceptSpec(t, "ACCEPT-FD:0", pipeFD), xio.ModeRDWR, nil)
	_ = unix.Close(pipeFD)
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("pipe err=%v want not a socket", err)
	}

	udp, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(udp) })
	_, err = openAcceptFD(context.Background(), parseAcceptSpec(t, "ACCEPT-FD:0", udp), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "datagram") {
		t.Fatalf("udp err=%v want datagram", err)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cli, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	tc, ok := srv.(*net.TCPConn)
	if !ok {
		t.Fatalf("accepted %T", srv)
	}
	f, err := tc.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	cfd := dupOwnedFD(t, int(f.Fd()))
	_, err = openAcceptFD(context.Background(), parseAcceptSpec(t, "ACCEPT-FD:0", cfd), xio.ModeRDWR, nil)
	_ = unix.Close(cfd)
	if err == nil || (!strings.Contains(err.Error(), "connected") && !strings.Contains(err.Error(), "not listening")) {
		t.Fatalf("connected socket err=%v want connected/not listening", err)
	}
}

func TestAcceptFDForkAcceptsMoreThanOne(t *testing.T) {
	fd, addr := tcp4ListenOwned(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := parseAcceptSpec(t, "ACCEPT-FD:0,fork", fd)
	g := &xio.Global{BlockSize: 8192, Log: logx.New(), Linger: 200 * time.Millisecond}
	o, err := openAcceptFD(ctx, s, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Listener == nil {
		t.Fatal("fork ACCEPT-FD must keep the listener")
	}
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = xio.RunOpened(ctx, o, pipe, g) }()

	for i, payload := range [][]byte{[]byte("first-fork"), []byte("second-fork")} {
		cli, err := net.DialTimeout("tcp4", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if _, err := cli.Write(payload); err != nil {
			_ = cli.Close()
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(cli, got); err != nil {
			_ = cli.Close()
			t.Fatalf("client %d read: %v", i, err)
		}
		_ = cli.Close()
		if string(got) != string(payload) {
			t.Fatalf("client %d got %q want %q", i, got, payload)
		}
	}
}

func TestAcceptFDRejectsListenSetsockopt(t *testing.T) {
	fd, _ := tcp4ListenOwned(t)
	s, err := parse.ParseSpec(fmt.Sprintf("ACCEPT-FD:0,setsockopt-listen=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	s.Params = []string{strconv.Itoa(fd)}
	_, err = openAcceptFD(context.Background(), s, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported at this lifecycle phase") {
		t.Fatalf("err=%v want lifecycle rejection", err)
	}
	_ = unix.Close(fd)
}

func TestAcceptFDWrongParamCount(t *testing.T) {
	_, err := openAcceptFD(context.Background(), parse.Spec{Type: "ACCEPT-FD"}, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "wrong number of parameters") {
		t.Fatalf("err=%v", err)
	}
}
