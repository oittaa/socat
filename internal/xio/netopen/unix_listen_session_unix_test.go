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

func TestUnixListenNonForkAccept(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	g := &xio.Global{Log: logx.New()}
	o := openUnixListenOnce(t, "UNIX-LISTEN:"+path+",unlink-early", g, func() {
		c, err := net.Dial("unix", path)
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
		t.Fatal("non-fork UNIX-LISTEN has no stream")
	}
	if g.SockAddr != path {
		t.Fatalf("SOCAT_SOCKADDR=%q want %q", g.SockAddr, path)
	}
	if g.PeerAddr == "" {
		t.Fatal("SOCAT_PEERADDR was not populated")
	}
}

func TestAbstractListenNonForkAccept(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("ABSTRACT UNIX not enabled")
	}
	name := t.Name()
	g := &xio.Global{Log: logx.New()}
	o := openUnixListenOnce(t, "ABSTRACT-LISTEN:"+name, g, func() {
		c, err := net.Dial("unix", "@"+name)
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
		t.Fatal("non-fork ABSTRACT-LISTEN has no stream")
	}
	if g.SockAddr == "" {
		t.Fatal("SOCAT_SOCKADDR was not populated")
	}
	if g.PeerAddr == "" {
		t.Fatal("SOCAT_PEERADDR was not populated")
	}
}

func TestUnixListenForkWrapDial(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixListen(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindListen {
		t.Fatalf("Kind=%v want KindListen", o.Kind)
	}
	if o.PeerFilter == nil {
		t.Fatal("fork UNIX-LISTEN must install PeerFilter")
	}
	assertWrapDialReadbytes(t, o)
}

func TestAbstractListenForkWrapDial(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("ABSTRACT UNIX not enabled")
	}
	spec, err := parse.ParseSpec("ABSTRACT-LISTEN:" + t.Name() + ",fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openAbstractListen(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindListen {
		t.Fatalf("Kind=%v want KindListen", o.Kind)
	}
	assertWrapDialReadbytes(t, o)
}

func TestUnixListenCancellation(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	bound := make(chan struct{})
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(net.Addr) {
		boundOnce.Do(func() { close(bound) })
	})()
	done := make(chan error, 1)
	go func() {
		_, err := openUnixListen(ctx, spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		done <- err
	}()
	select {
	case <-bound:
	case err := <-done:
		t.Fatalf("listen ended before bind: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("UNIX-LISTEN did not bind")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled UNIX-LISTEN did not return")
	}
}

func TestUnixListenAcceptTimeoutPositive(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,accept-timeout=0.2")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = openUnixListen(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("error=%v want ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("accept-timeout elapsed %s", elapsed)
	}
}

func TestUnixListenAcceptTimeoutZeroAccepts(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	g := &xio.Global{Log: logx.New()}
	o := openUnixListenOnce(t, "UNIX-LISTEN:"+path+",unlink-early,accept-timeout=0", g, func() {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { _ = c.Close() })
	})
	if o.Stream == nil {
		t.Fatal("accept-timeout=0 did not accept")
	}
}

func TestUnixListenSessionEnv(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	g := &xio.Global{Log: logx.New()}
	o := openUnixListenOnce(t, "UNIX-LISTEN:"+path+",unlink-early", g, func() {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { _ = c.Close() })
	})
	if _, err := o.Stream.Write([]byte("x")); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("write: %v", err)
	}
	if g.SockAddr != path {
		t.Fatalf("SOCAT_SOCKADDR=%q want listen path", g.SockAddr)
	}
	if g.SockPort != "" || g.PeerPort != "" {
		t.Fatalf("ports SockPort=%q PeerPort=%q want empty", g.SockPort, g.PeerPort)
	}
	if g.PeerAddr == "" {
		t.Fatal("SOCAT_PEERADDR empty")
	}
}

func openUnixListenOnce(t *testing.T, raw string, g *xio.Global, afterBind func()) *xio.Opened {
	t.Helper()
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	open := openUnixListen
	if spec.Type == "ABSTRACT-LISTEN" {
		open = openAbstractListen
	}
	bound := make(chan struct{})
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(net.Addr) {
		boundOnce.Do(func() { close(bound) })
	})()
	type result struct {
		o   *xio.Opened
		err error
	}
	done := make(chan result, 1)
	go func() {
		o, err := open(context.Background(), spec, xio.ModeRDWR, g)
		done <- result{o, err}
	}()
	select {
	case <-bound:
	case r := <-done:
		t.Fatalf("listen ended before bind: %v", r.err)
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not bind")
	}
	afterBind()
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
