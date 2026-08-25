//go:build unix

package netopen

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUNIXListenConnectEcho(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	path := filepath.Join(t.TempDir(), "app.sock")
	ls, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",unlink-early,fork")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := openUnixListen(context.Background(), ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if srv.Listener == nil {
		t.Fatal("UNIX-LISTEN did not return a listener")
	}
	echoAccepted(t, srv.Listener)
	cs, err := parse.ParseSpec("UNIX-CONNECT:" + path)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := openUnixConnect(context.Background(), cs, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	const payload = "unix-hello"
	if _, err := io.WriteString(cli.Stream, payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(cli.Stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("UNIX echo got %q", buf)
	}
}
