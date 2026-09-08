package netopen

import (
	"io"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func assertWrapDialReadbytes(t *testing.T, o *xio.Opened) {
	t.Helper()
	if o.WrapDial == nil {
		t.Fatal("WrapDial is nil")
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
}
