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

func TestAcceptWithTimeoutCanceledWithoutTimeout(t *testing.T) {
	ln := newCloseOnlyListener()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := AcceptWithTimeout(ctx, ln, 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v want context.Canceled", err)
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

func TestOpenedCloseOrderReady(t *testing.T) {
	var order []string
	o, err := NewReady("", relay.FDStream{C: orderCloser{name: "stream", order: &order}})
	if err != nil {
		t.Fatal(err)
	}
	o.AddTTYRestore(func() { order = append(order, "tty") })
	o.AddCleanup(func() { order = append(order, "cleanup") })
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, " ") != "tty stream cleanup" {
		t.Fatalf("%q", order)
	}
}

func TestOpenedCloseOrderAccept(t *testing.T) {
	var order []string
	o, err := NewAcceptParent("", AcceptParent{
		Listener: orderListener{orderCloser{name: "listener", order: &order}},
	})
	if err != nil {
		t.Fatal(err)
	}
	o.AddCleanup(func() { order = append(order, "cleanup") })
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, " ") != "listener cleanup" {
		t.Fatalf("%q", order)
	}
}

func TestOpenedCloseOrderReadySplit(t *testing.T) {
	var order []string
	o, err := NewReadySplit("",
		relay.FDStream{C: orderCloser{name: "read", order: &order}},
		relay.FDStream{C: orderCloser{name: "write", order: &order}},
	)
	if err != nil {
		t.Fatal(err)
	}
	o.AddCleanup(func() { order = append(order, "cleanup") })
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, " ") != "read write cleanup" {
		t.Fatalf("%q", order)
	}
}
