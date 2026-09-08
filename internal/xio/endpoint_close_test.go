package xio

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type closeOnlyListener struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseOnlyListener() *closeOnlyListener {
	return &closeOnlyListener{closed: make(chan struct{})}
}

func (l *closeOnlyListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *closeOnlyListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *closeOnlyListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAcceptWithTimeoutWithoutDeadlineSupport(t *testing.T) {
	ln := newCloseOnlyListener()
	start := time.Now()
	_, err := AcceptWithTimeout(context.Background(), ln, 30*time.Millisecond)
	if !errors.Is(err, ErrAcceptTimeout) {
		t.Fatalf("error=%v want ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("accept timeout took %s", elapsed)
	}
}
