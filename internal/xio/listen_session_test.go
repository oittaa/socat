package xio

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
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
	_, err := OpenListenSession(ctx, parseSpecForListenSession(t, "TCP-LISTEN:0"), nil, ListenSession{Listener: ln})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenListenSession error=%v, want context.Canceled", err)
	}
}

func TestOpenListenSessionClosesKeptListenerOnWrapError(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	wantErr := errors.New("wrap failed")
	ln := &testSessionListener{conn: server, closed: make(chan struct{})}
	_, err := OpenListenSession(context.Background(), parseSpecForListenSession(t, "QUIC-LISTEN:0"), nil, ListenSession{
		Listener:               ln,
		KeepListenerForSession: true,
		WrapDial: func(net.Conn) (relay.Stream, error) {
			return nil, wantErr
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("OpenListenSession error=%v, want %v", err, wantErr)
	}
	select {
	case <-ln.closed:
	default:
		t.Fatal("kept listener was not closed after wrap failure")
	}
}
