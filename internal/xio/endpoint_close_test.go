package xio

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/relay"
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

type orderCloser struct {
	name  string
	order *[]string
}

func (c orderCloser) Close() error {
	*c.order = append(*c.order, c.name)
	return nil
}

type orderListener struct{ orderCloser }

func (orderListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (orderListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestOpenedCloseOrder(t *testing.T) {
	var order []string
	o := &Opened{
		Stream:   relay.FDStream{C: orderCloser{name: "stream", order: &order}},
		Listener: orderListener{orderCloser{name: "listener", order: &order}},
	}
	o.AddTTYRestore(func() { order = append(order, "tty") })
	o.AddCleanup(func() { order = append(order, "cleanup") })
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, " ") != "tty stream listener cleanup" {
		t.Fatalf("%q", order)
	}
}
