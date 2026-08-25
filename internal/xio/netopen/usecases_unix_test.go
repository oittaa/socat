//go:build unix

package netopen

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func TestUNIXListenConnectUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "use.sock")
	startNetListenPIPE(t, ctx, useGlobal(), "UNIX-LISTEN:"+path+",unlink-early,fork")
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "UNIX-CONNECT:"+path), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("unix-use"))
}

func TestUNIXClientUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "client.sock")
	startNetListenPIPE(t, ctx, useGlobal(), "UNIX-LISTEN:"+path+",unlink-early,fork")
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "UNIX-CLIENT:"+path), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("unix-client-use"))
}

func TestUNIXSendtoRecvUseCase(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "dgram.sock")
	recv, err := xio.OpenChannel(ctx, parseChannel(t, "UNIX-RECV:"+path+",unlink-early"), xio.ModeRead, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	send, err := xio.OpenChannel(ctx, parseChannel(t, "UNIX-SENDTO:"+path), xio.ModeWrite, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "unix-dgram-use"
	if _, err := send.Stream.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if d, ok := recv.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	if _, err := io.ReadFull(recv.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("UNIX-RECV got %q", got)
	}
}
