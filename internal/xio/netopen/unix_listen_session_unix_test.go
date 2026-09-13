//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixListenPeerEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fork  bool
		named bool
	}{
		{"non-fork unnamed", false, false},
		{"non-fork named", false, true},
		{"fork unnamed", true, false},
		{"fork named", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := unixSocketTestPath(t, "listen.sock")
			bind := ""
			wantPeer := path
			if tc.named {
				bind = unixSocketTestPath(t, "client.sock")
				wantPeer = bind
			}
			if tc.fork {
				sock, peer, sockPort, peerPort, parent := unixListenForkEnv(t, "UNIX-LISTEN:"+path+",unlink-early,fork", path, bind)
				if sock != path || peer != wantPeer || sockPort != "" || peerPort != "" {
					t.Fatalf("SOCKADDR=%q PEERADDR=%q SOCKPORT=%q PEERPORT=%q", sock, peer, sockPort, peerPort)
				}
				if parent.SockAddr != "" || parent.PeerAddr != "" || parent.SockPort != "" || parent.PeerPort != "" {
					t.Fatalf("parent peer %+v", parent)
				}
				return
			}
			g := &xio.Global{Log: logx.New()}
			openUnixListenOnce(t, "UNIX-LISTEN:"+path+",unlink-early", g, func() {
				_ = dialUnixPeer(t, path, bind)
			})
			assertFilesystemListenPeer(t, g, path, wantPeer)
		})
	}
}

func TestAbstractListenPeerEnvironment(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("ABSTRACT UNIX not enabled")
	}
	for _, fork := range []bool{false, true} {
		name := "non-fork"
		if fork {
			name = "fork"
		}
		t.Run(name, func(t *testing.T) {
			abs := "p2-" + name
			dial := "@" + abs
			if fork {
				sock, peer, _, _, parent := unixListenForkEnv(t, "ABSTRACT-LISTEN:"+abs+",fork", dial, "")
				if sock == "" || peer == "" {
					t.Fatalf("SOCKADDR=%q PEERADDR=%q", sock, peer)
				}
				if parent.SockAddr != "" || parent.PeerAddr != "" {
					t.Fatalf("parent peer %+v", parent)
				}
				return
			}
			g := &xio.Global{Log: logx.New()}
			openUnixListenOnce(t, "ABSTRACT-LISTEN:"+abs, g, func() {
				_ = dialUnixPeer(t, dial, "")
			})
			if g.Peer.SockAddr == "" || g.Peer.PeerAddr == "" {
				t.Fatalf("SOCKADDR=%q PEERADDR=%q", g.Peer.SockAddr, g.Peer.PeerAddr)
			}
		})
	}
}

func TestUnixListenForkWrapDial(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixListen(context.Background(), mustAddr(t, spec), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind() != xio.KindListen {
		t.Fatalf("Kind=%v want KindListen", o.Kind())
	}
	if o.PeerFilter() == nil {
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
	o, err := openAbstractListen(context.Background(), mustAddr(t, spec), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind() != xio.KindListen {
		t.Fatalf("Kind=%v want KindListen", o.Kind())
	}
	assertWrapDialReadbytes(t, o)
}

func TestUnixListenAcceptTimeoutPositive(t *testing.T) {
	path := unixSocketTestPath(t, "listen.sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,accept-timeout=0.2")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = openUnixListen(context.Background(), mustAddr(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
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
	if o.Stream() == nil {
		t.Fatal("accept-timeout=0 did not accept")
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
		o, err := open(context.Background(), mustAddr(t, spec), xio.ModeRDWR, g)
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

func assertFilesystemListenPeer(t *testing.T, g *xio.Global, sock, peer string) {
	t.Helper()
	if g.Peer.SockAddr != sock {
		t.Fatalf("SOCAT_SOCKADDR=%q want %q", g.Peer.SockAddr, sock)
	}
	if g.Peer.PeerAddr != peer {
		t.Fatalf("SOCAT_PEERADDR=%q want %q", g.Peer.PeerAddr, peer)
	}
	if g.Peer.SockPort != "" || g.Peer.PeerPort != "" {
		t.Fatalf("ports SockPort=%q PeerPort=%q want empty", g.Peer.SockPort, g.Peer.PeerPort)
	}
}

func dialUnixPeer(t *testing.T, path, bind string) net.Conn {
	t.Helper()
	var laddr *net.UnixAddr
	if bind != "" {
		laddr = &net.UnixAddr{Name: bind, Net: "unix"}
	}
	c, err := net.DialUnix("unix", laddr, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func unixListenForkEnv(t *testing.T, listenSpec, dialPath, bind string) (sock, peer, sockPort, peerPort string, parent xio.Peer) {
	t.Helper()
	if !xio.FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	script := filepath.Join(t.TempDir(), "env.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$SOCAT_SOCKADDR\" \"$SOCAT_PEERADDR\" \"$SOCAT_SOCKPORT\" \"$SOCAT_PEERPORT\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec(listenSpec)
	if err != nil {
		t.Fatal(err)
	}
	open := openUnixListen
	if spec.Type == "ABSTRACT-LISTEN" {
		open = openAbstractListen
	}
	g := xio.NewSession(xio.Options{BlockSize: 8192}, logx.New())
	o, err := open(context.Background(), mustAddr(t, spec), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	right := parseChannel(t, "EXEC:"+script)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = xio.RunOpened(ctx, o, right, g)
	}()
	c := dialUnixPeer(t, dialPath, bind)
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("env %q", got)
	}
	return lines[0], lines[1], lines[2], lines[3], g.Peer
}
