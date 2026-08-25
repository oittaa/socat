package xio

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestOpenDialedForkSetsDefaultWrapDial(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:1,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenDialed(context.Background(), s, &Global{BlockSize: 8192, Log: logx.New()}, Dialed{
		Label: "tcp-fork",
		Dial: func(context.Context) (net.Conn, error) {
			t.Fatal("fork open must not dial")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != KindDial {
		t.Fatalf("kind=%v", o.Kind)
	}
	if o.WrapDial == nil {
		t.Fatal("fork dialer must provide WrapDial")
	}
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	st, err := o.WrapDial(a)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = b.Write([]byte("hello"))
		_ = b.Close()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hell" {
		t.Fatalf("readbytes wrap got %q want hell", got)
	}
	_ = relay.Stream(st)
}
