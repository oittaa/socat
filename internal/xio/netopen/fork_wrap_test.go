package netopen

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestForkListenersWrapDialAppliesReadbytes(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	ctx := context.Background()

	t.Run("udp-listen", func(t *testing.T) {
		spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,readbytes=4")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openUDP4Listen(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertWrapDialReadbytes(t, o)
	})

	t.Run("udp-recvfrom", func(t *testing.T) {
		spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork,readbytes=4")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openUDP4Recvfrom(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertWrapDialReadbytes(t, o)
	})

	if runtime.GOOS == "windows" {
		return
	}

	t.Run("unix-listen", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "listen.sock")
		spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,fork,readbytes=4")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openUnixListen(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertWrapDialReadbytes(t, o)
	})

	t.Run("unix-recvfrom", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "recv.sock")
		spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,readbytes=4")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openUnixRecvfrom(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertWrapDialReadbytes(t, o)
	})

	if runtime.GOOS == "linux" {
		t.Run("abstract-listen", func(t *testing.T) {
			spec, err := parse.ParseSpec("ABSTRACT-LISTEN:" + filepath.Base(t.TempDir()) + ",fork,readbytes=4")
			if err != nil {
				t.Fatal(err)
			}
			o, err := openAbstractListen(ctx, spec, xio.ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			assertWrapDialReadbytes(t, o)
		})
	}
}

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
