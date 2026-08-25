//go:build unix

package netopen

import (
	"context"
	"runtime"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestForkListenersWrapDialAppliesReadbytesUnix(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	ctx := context.Background()

	t.Run("unix-listen", func(t *testing.T) {
		path := unixSocketTestPath(t, "listen.sock")
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
		path := unixSocketTestPath(t, "recv.sock")
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
			spec, err := parse.ParseSpec("ABSTRACT-LISTEN:" + t.Name() + ",fork,readbytes=4")
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

func TestSocketListenForkHasWrapDial(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("SOCKET-LISTEN:2:0:x00007f000001,reuseaddr,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openSocketListen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.PeerFilter == nil {
		t.Fatal("SOCKET-LISTEN must install PeerFilter")
	}
	assertWrapDialReadbytes(t, o)
}
