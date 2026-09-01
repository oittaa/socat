//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketConnectTimeoutDoesNotHang(t *testing.T) {
	spec := "SOCKET-CONNECT:2:0:" + ipv4SocketHex(80, [4]byte{192, 0, 2, 1}) + ",connect-timeout=0.3"
	start := time.Now()
	o, err := openSocketConnect(context.Background(), mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	elapsed := time.Since(start)
	if o != nil {
		_ = o.Close()
	}
	if err == nil {
		t.Fatal("connect to 192.0.2.1 succeeded")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("connect-timeout hung for %s: %v", elapsed, err)
	}
	if elapsed < 200*time.Millisecond {
		t.Logf("connect returned in %s (%v); TEST-NET-1 was not blackholed", elapsed, err)
		return
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connect-timeout err=%v want context.DeadlineExceeded (elapsed %s)", err, elapsed)
	}
}

func TestSocketConnectCancelAborts(t *testing.T) {
	spec := "SOCKET-CONNECT:2:0:" + ipv4SocketHex(80, [4]byte{192, 0, 2, 1}) + ",connect-timeout=5"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := openSocketConnect(ctx, mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled connect succeeded")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("canceled connect hung for %s: %v", elapsed, err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Logf("canceled connect err=%v (peer may have refused immediately)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled SOCKET-CONNECT did not return")
	}
}

func TestSocketConnectRetryWaitsBetweenAttempts(t *testing.T) {
	spec := "SOCKET-CONNECT:2:0:" + ipv4SocketHex(1, [4]byte{127, 0, 0, 1}) + ",retry=1,interval=0.15"
	start := time.Now()
	_, err := openSocketConnect(context.Background(), mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("connect to 127.0.0.1:1 succeeded")
	}
	if elapsed < 120*time.Millisecond {
		t.Fatalf("retry did not wait interval: elapsed %s err=%v", elapsed, err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("retry hung for %s: %v", elapsed, err)
	}
}

func TestSocketConnectForkDoesNotDialAtOpen(t *testing.T) {
	spec := "SOCKET-CONNECT:2:0:" + ipv4SocketHex(80, [4]byte{192, 0, 2, 1}) + ",fork,interval=0.15"
	o, err := openSocketConnect(context.Background(), mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindDial {
		t.Fatalf("Kind=%v want KindDial", o.Kind)
	}
	if o.Dial == nil {
		t.Fatal("fork SOCKET-CONNECT must provide Dial")
	}
	if o.WrapDial == nil {
		t.Fatal("fork SOCKET-CONNECT must provide WrapDial")
	}
	if o.Stream != nil {
		t.Fatal("fork open must not connect a stream")
	}
	if o.Interval != 150*time.Millisecond {
		t.Fatalf("Interval=%s want 150ms", o.Interval)
	}
}

func TestSocketConnectForkDialConnects(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 8)
		n, err := c.Read(buf)
		if err != nil && err != io.EOF {
			done <- err
			return
		}
		_, err = c.Write(buf[:n])
		done <- err
	}()

	spec := "SOCKET-CONNECT:2:0:" + ipv4SocketHex(port, [4]byte{127, 0, 0, 1}) + ",fork"
	o, err := openSocketConnect(context.Background(), mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Stream != nil {
		t.Fatal("fork open connected before Dial")
	}
	conn, err := o.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st, err := o.WrapDial(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := st.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("got %q", buf[:n])
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accept/echo timed out")
	}
}

func TestSocketListenCancellation(t *testing.T) {
	spec := "SOCKET-LISTEN:2:0:" + ipv4SocketHex(0, [4]byte{127, 0, 0, 1}) + ",reuseaddr"
	ctx, cancel := context.WithCancel(context.Background())
	bound := make(chan struct{})
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(net.Addr) {
		boundOnce.Do(func() { close(bound) })
	})()
	done := make(chan error, 1)
	go func() {
		_, err := openSocketListen(ctx, mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
		done <- err
	}()
	select {
	case <-bound:
	case err := <-done:
		t.Fatalf("listen ended before bind: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKET-LISTEN did not bind")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled SOCKET-LISTEN did not return")
	}
}

func TestSocketListenAcceptTimeout(t *testing.T) {
	spec := "SOCKET-LISTEN:2:0:" + ipv4SocketHex(0, [4]byte{127, 0, 0, 1}) + ",reuseaddr,accept-timeout=0.2"
	start := time.Now()
	_, err := openSocketListen(context.Background(), mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("error=%v want ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("accept-timeout elapsed %s", elapsed)
	}
}

func TestSocketListenNonForkPeerAddrAndRange(t *testing.T) {
	g := &xio.Global{Log: logx.New()}
	o := openSocketListenOnce(t, "SOCKET-LISTEN:2:0:"+ipv4SocketHex(0, [4]byte{127, 0, 0, 1})+",reuseaddr,range=127.0.0.0/8", g, func(addr net.Addr) {
		c, err := net.Dial("tcp4", addr.String())
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { _ = c.Close() })
	})
	if o.Kind != xio.KindReady {
		t.Fatalf("Kind=%v want KindReady", o.Kind)
	}
	if o.Stream == nil {
		t.Fatal("non-fork SOCKET-LISTEN has no stream")
	}
	if g.PeerAddr != "127.0.0.1" {
		t.Fatalf("SOCAT_PEERADDR=%q want 127.0.0.1", g.PeerAddr)
	}
	if g.PeerPort == "" {
		t.Fatal("SOCAT_PEERPORT was not populated")
	}
}

func TestSocketListenRangeRefusesThenAcceptTimeout(t *testing.T) {
	spec := "SOCKET-LISTEN:2:0:" + ipv4SocketHex(0, [4]byte{127, 0, 0, 1}) + ",reuseaddr,range=10.0.0.0/8,accept-timeout=0.25"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		err error
	}
	done := make(chan result, 1)
	bound := make(chan net.Addr, 1)
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(addr net.Addr) {
		boundOnce.Do(func() { bound <- addr })
	})()
	go func() {
		_, err := openSocketListen(ctx, mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
		done <- result{err}
	}()
	var addr net.Addr
	select {
	case addr = <-bound:
	case r := <-done:
		t.Fatalf("listen ended before bind: %v", r.err)
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKET-LISTEN did not bind")
	}
	c, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, c)
	_ = c.Close()
	select {
	case r := <-done:
		if !errors.Is(r.err, xio.ErrAcceptTimeout) {
			t.Fatalf("error=%v want ErrAcceptTimeout after range refuse", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("range-refused SOCKET-LISTEN did not time out")
	}
}

func openSocketListenOnce(t *testing.T, raw string, g *xio.Global, afterBind func(net.Addr)) *xio.Opened {
	t.Helper()
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	bound := make(chan net.Addr, 1)
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(addr net.Addr) {
		boundOnce.Do(func() { bound <- addr })
	})()
	type result struct {
		o   *xio.Opened
		err error
	}
	done := make(chan result, 1)
	go func() {
		o, err := openSocketListen(context.Background(), spec, xio.ModeRDWR, g)
		done <- result{o, err}
	}()
	var addr net.Addr
	select {
	case addr = <-bound:
	case r := <-done:
		t.Fatalf("listen ended before bind: %v", r.err)
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not bind")
	}
	afterBind(addr)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { _ = r.o.Close() })
		return r.o
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not accept")
	}
	return nil
}
