package xio

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/oittaa/socat/internal/parse"
)

type testSessionListener struct {
	conn      net.Conn
	acceptErr error
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *testSessionListener) Accept() (net.Conn, error) {
	if l.conn != nil || l.acceptErr != nil {
		conn, err := l.conn, l.acceptErr
		l.conn = nil
		l.acceptErr = net.ErrClosed
		return conn, err
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *testSessionListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *testSessionListener) Addr() net.Addr { return testSessionAddr("test") }

type testSessionAddr string

func (a testSessionAddr) Network() string { return string(a) }
func (a testSessionAddr) String() string  { return string(a) }

func parseSpecForListenSession(t *testing.T, value string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(value)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpenListenSessionReturnsParentCancellation(t *testing.T) {
	ln := &testSessionListener{closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := OpenListenSession(ctx, mustDecodeAddress(t, parseSpecForListenSession(t, "TCP-LISTEN:0")), nil, ListenSession{Listener: ln})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenListenSession error=%v, want context.Canceled", err)
	}
}

func TestOpenListenSessionAcceptTimeoutWithoutDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ln := &testSessionListener{closed: make(chan struct{})}
		_, err := OpenListenSession(context.Background(), mustDecodeAddress(t, parseSpecForListenSession(t, "TCP-LISTEN:0,accept-timeout=0.05")), nil, ListenSession{Listener: ln})
		if !errors.Is(err, ErrAcceptTimeout) {
			t.Fatalf("OpenListenSession error=%v, want ErrAcceptTimeout", err)
		}
	})
}
