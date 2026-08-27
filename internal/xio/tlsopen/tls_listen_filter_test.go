package tlsopen

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
)

func TestTLSListenNonForkRetriesRejectedPeer(t *testing.T) {
	certPath, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln0, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln0.Addr().(*net.TCPAddr).Port
	_ = ln0.Close()

	spec, err := parse.ParseSpec(
		"TLS-LISTEN:" + strconv.Itoa(port) + ",reuseaddr,bind=127.0.0.1,verify=0,cert=" + certPath + ",range=127.0.0.1,accept-timeout=2",
	)
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		o   *xio.Opened
		err error
	}
	done := make(chan result, 1)
	bound := make(chan struct{})
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func() {
		boundOnce.Do(func() { close(bound) })
	})()
	go func() {
		o, err := openTLSListen(ctx, spec, xio.ModeRDWR, g)
		done <- result{o, err}
	}()
	waitListenBound(t, bound, done, 5*time.Second)

	refuse := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	raw, err := refuse.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	_ = tc.Handshake()
	_ = tc.Close()

	raw, err = net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("matching peer dial: %v", err)
	}
	ok := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := ok.Handshake(); err != nil {
		t.Fatalf("matching peer handshake: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("listen: %v", r.err)
		}
		t.Cleanup(func() {
			_ = ok.Close()
			if r.o != nil {
				_ = r.o.Close()
			}
		})
	case <-time.After(3 * time.Second):
		t.Fatal("TLS-LISTEN did not accept the matching peer after a refusal")
	}
}

func TestTLSListenNonForkRestartsAcceptTimeoutAfterRefusedPeer(t *testing.T) {
	certPath, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln0, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln0.Addr().(*net.TCPAddr).Port
	_ = ln0.Close()

	spec, err := parse.ParseSpec(
		"TLS-LISTEN:" + strconv.Itoa(port) + ",reuseaddr,bind=127.0.0.1,verify=0,cert=" + certPath + ",range=127.0.0.1,accept-timeout=0.30",
	)
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	bound := make(chan struct{})
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func() {
		boundOnce.Do(func() { close(bound) })
	})()
	go func() {
		_, err := openTLSListen(ctx, spec, xio.ModeRDWR, g)
		errCh <- err
	}()
	waitListenBound(t, bound, errCh, 5*time.Second)
	start := time.Now()
	time.Sleep(180 * time.Millisecond)

	refuse := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	if raw, err := refuse.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
		_ = tc.Handshake()
		_ = tc.Close()
	} else {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}

	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if !errors.Is(err, xio.ErrAcceptTimeout) {
			t.Fatalf("error=%v want ErrAcceptTimeout after %s", err, elapsed)
		}
		if elapsed < 430*time.Millisecond {
			t.Fatalf("accept-timeout took %s; deadline was not restarted after the refused peer", elapsed)
		}
		if elapsed > 850*time.Millisecond {
			t.Fatalf("accept-timeout took unexpectedly long: %s", elapsed)
		}
	case <-time.After(1200 * time.Millisecond):
		t.Fatal("TLS-LISTEN did not time out after the refused peer")
	}
}

func waitListenBound[T any](t *testing.T, bound <-chan struct{}, failed <-chan T, timeout time.Duration) {
	t.Helper()
	select {
	case <-bound:
	case v := <-failed:
		t.Fatalf("listen returned before bind: %v", v)
	case <-time.After(timeout):
		t.Fatal("timeout waiting for TCP listen")
	}
}
