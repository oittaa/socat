//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixConnectBindUnlinkEarlyReplacesFile(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)
	if err := os.WriteFile(bind, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	o := openBoundUnixConnect(t, listen, bind, parse.Option{Name: "unlink-early"})
	t.Cleanup(func() { _ = o.Close() })
	fi, err := os.Lstat(bind)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("unlink-early left mode=%v want socket", fi.Mode())
	}
}

func TestUnixConnectBindPreservesLiveListenSocket(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "occupied.sock")
	startUnixStreamPeer(t, listen)
	startUnixStreamPeer(t, bind)

	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{listen},
		Options: []parse.Option{{Name: "bind", Value: bind, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected bind of live listen socket to fail")
	}
	if _, statErr := os.Lstat(bind); statErr != nil {
		t.Fatalf("live listen socket was removed: %v", statErr)
	}
}

func TestUnixConnectFailedOpenUnlinksOnlyCreatedBind(t *testing.T) {
	missing := unixSocketTestPath(t, "missing.sock")
	bind := unixSocketTestPath(t, "client.sock")
	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{missing},
		Options: []parse.Option{{Name: "bind", Value: bind, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected connect to missing dest to fail")
	}
	if _, statErr := os.Lstat(bind); !os.IsNotExist(statErr) {
		t.Fatalf("created bind path survived failed connect: %v", statErr)
	}
}

func TestUnixSendtoHonorsCanceledContext(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	remote := unixSocketTestPath(t, "cancel.sock")
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",forever,interval=1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = openUnixSendto(ctx, mustAddr(t, spec), xio.ModeWrite, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context canceled", err)
	}
}

func TestUnixRecvRejectsWriteModeAtOpen(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	path := unixSocketTestPath(t, "recv.sock")
	spec, err := parse.ParseSpec("UNIX-RECV:" + path)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecv(context.Background(), mustAddr(t, spec), xio.ModeWrite, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected write-mode UNIX-RECV to fail at open")
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("read-only open created %s: %v", path, statErr)
	}
}

func TestAbstractRecvRejectsWriteModeAtOpen(t *testing.T) {
	if !xio.FeatureUNIXDatagram || !xio.FeatureABSTRACT {
		t.Skip("abstract UNIX datagram not enabled")
	}
	spec, err := parse.ParseSpec("ABSTRACT-RECV:" + filepath.Base(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openAbstractRecv(context.Background(), mustAddr(t, spec), xio.ModeWrite, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected write-mode ABSTRACT-RECV to fail at open")
	}
}

func TestUnixgramUnnamedAndNamedPeerMatch(t *testing.T) {
	dest := &net.UnixAddr{Name: "/tmp/dest.sock", Net: "unixgram"}
	if !unixgramAcceptSender(nil, dest) {
		t.Fatal("nil sender must be accepted")
	}
	if !unixgramAcceptSender(&net.UnixAddr{Name: "", Net: "unixgram"}, dest) {
		t.Fatal("unnamed sender must be accepted")
	}
	if !unixgramAcceptSender(&net.UnixAddr{Name: "\x00", Net: "unixgram"}, dest) {
		t.Fatal("abstract unnamed sender must be accepted")
	}
	if unixgramAcceptSender(&net.UnixAddr{Name: "/tmp/wrong.sock", Net: "unixgram"}, dest) {
		t.Fatal("named wrong peer must be rejected")
	}
	if !unixgramAcceptSender(dest, dest) {
		t.Fatal("configured peer must be accepted")
	}
}

func TestUnixgramConnReadDoesNotHangOnEOF(t *testing.T) {
	c, err := listenUnixgramUnbound(mustAddr(t, parse.Spec{Type: "UNIX-SENDTO"}))
	if err != nil {
		t.Fatal(err)
	}
	u := &unixgramConn{UnixConn: c, raddr: &net.UnixAddr{Name: "x", Net: "unixgram"}, filterPeer: true, ctx: context.Background()}
	_ = c.Close()
	_, err = u.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("expected read error after close")
	}
	if errors.Is(err, io.EOF) {
		return
	}
}
