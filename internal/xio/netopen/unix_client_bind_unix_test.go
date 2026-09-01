//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestUnixConnectBindPreservesExistingFile(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	bind := unixSocketTestPath(t, "client.sock")
	startUnixStreamPeer(t, listen)
	if err := os.WriteFile(bind, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{listen},
		Options: []parse.Option{{Name: "bind", Value: bind, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected bind of existing file to fail")
	}
	if !errors.Is(err, syscall.EADDRINUSE) && !errors.Is(err, unix.EADDRINUSE) {
		t.Fatalf("err=%v want EADDRINUSE", err)
	}
	data, readErr := os.ReadFile(bind)
	if readErr != nil {
		t.Fatalf("existing bind path was removed: %v", readErr)
	}
	if string(data) != "keep" {
		t.Fatalf("bind path contents=%q", data)
	}
}

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
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected bind of live listen socket to fail")
	}
	if _, statErr := os.Lstat(bind); statErr != nil {
		t.Fatalf("live listen socket was removed: %v", statErr)
	}
}

func TestUnixConnectBindPreservesSymlink(t *testing.T) {
	listen := unixSocketTestPath(t, "listen.sock")
	target := unixSocketTestPath(t, "target")
	bind := unixSocketTestPath(t, "link.sock")
	startUnixStreamPeer(t, listen)
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, bind); err != nil {
		t.Fatal(err)
	}

	spec := parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{listen},
		Options: []parse.Option{{Name: "bind", Value: bind, Has: true}},
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected bind of symlink to fail")
	}
	fi, err := os.Lstat(bind)
	if err != nil {
		t.Fatalf("symlink was removed: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("mode=%v want symlink", fi.Mode())
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "target" {
		t.Fatalf("symlink target changed: %v %q", err, data)
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
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected connect to missing dest to fail")
	}
	if _, statErr := os.Lstat(bind); !os.IsNotExist(statErr) {
		t.Fatalf("created bind path survived failed connect: %v", statErr)
	}
}

func TestUnixSendtoBindPreservesExistingFile(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	local := unixSocketTestPath(t, "local.sock")
	remote := unixSocketTestPath(t, "remote.sock")
	if err := os.WriteFile(local, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",bind=" + local)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeWrite, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected bind of existing file to fail")
	}
	data, readErr := os.ReadFile(local)
	if readErr != nil {
		t.Fatalf("existing bind path was removed: %v", readErr)
	}
	if string(data) != "keep" {
		t.Fatalf("bind path contents=%q", data)
	}
}

func TestUnixSendtoOpensWithoutDestination(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	remote := unixSocketTestPath(t, "late.sock")
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",forever,interval=0.2")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	o, err := openUnixSendto(ctx, spec, xio.ModeWrite, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if elapsed > 500*time.Millisecond {
		t.Fatalf("SENDTO open waited %s for a missing destination", elapsed)
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
	_, err = openUnixSendto(ctx, spec, xio.ModeWrite, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context canceled", err)
	}
}

func TestUnixSendtoDropsNamedWrongPeer(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	local := unixSocketTestPath(t, "local.sock")
	dest := unixSocketTestPath(t, "dest.sock")
	wrong := unixSocketTestPath(t, "wrong.sock")

	destConn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: dest, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destConn.Close() })
	wrongConn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: wrong, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrongConn.Close() })

	spec, err := parse.ParseSpec("UNIX-SENDTO:" + dest + ",bind=" + local)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	laddr := &net.UnixAddr{Name: local, Net: "unixgram"}
	if _, err := wrongConn.WriteToUnix([]byte("NAMED-WRONG\n"), laddr); err != nil {
		t.Fatal(err)
	}
	if _, err := destConn.WriteToUnix([]byte("FROM-DEST\n"), laddr); err != nil {
		t.Fatal(err)
	}

	_ = o.Stream.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "FROM-DEST\n" {
		t.Fatalf("read %q want FROM-DEST (named wrong peer must be dropped)", buf[:n])
	}
}

func TestUnixSendtoAcceptsUnnamedSender(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	local := unixSocketTestPath(t, "local.sock")
	dest := unixSocketTestPath(t, "dest.sock")
	destConn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: dest, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destConn.Close() })

	spec, err := parse.ParseSpec("UNIX-SENDTO:" + dest + ",bind=" + local)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unnamed := os.NewFile(uintptr(fd), "unnamed-unixgram")
	pc, err := net.FilePacketConn(unnamed)
	_ = unnamed.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc, ok := pc.(*net.UnixConn)
	if !ok {
		t.Fatalf("got %T", pc)
	}
	if _, err := uc.WriteToUnix([]byte("UNNAMED\n"), &net.UnixAddr{Name: local, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}

	_ = o.Stream.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "UNNAMED\n" {
		t.Fatalf("read %q want UNNAMED", buf[:n])
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
	o, err := openUnixRecv(context.Background(), spec, xio.ModeWrite, nil)
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
	o, err := openAbstractRecv(context.Background(), spec, xio.ModeWrite, nil)
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

func TestUnixSendtoWriteReachesLateDestination(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	dest := unixSocketTestPath(t, "dest.sock")
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + dest)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	recv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: dest, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	if _, err := o.Stream.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	_ = recv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := recv.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "late" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestAbstractSendtoDropsNamedWrongPeer(t *testing.T) {
	if !xio.FeatureUNIXDatagram || !xio.FeatureABSTRACT {
		t.Skip("abstract UNIX datagram not enabled")
	}
	dest := "\x00" + "socat-abs-sendto-dest-" + t.Name()
	local := "\x00" + "socat-abs-sendto-local-" + t.Name()
	wrong := "\x00" + "socat-abs-sendto-wrong-" + t.Name()

	destConn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: dest, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destConn.Close() })
	wrongConn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: wrong, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrongConn.Close() })

	spec := parse.Spec{
		Type:    "ABSTRACT-SENDTO",
		Params:  []string{dest},
		Options: []parse.Option{{Name: "bind", Value: local, Has: true}},
	}
	o, err := openAbstractSendto(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	laddr := &net.UnixAddr{Name: local, Net: "unixgram"}
	if _, err := wrongConn.WriteToUnix([]byte("WRONG"), laddr); err != nil {
		t.Fatal(err)
	}
	if _, err := destConn.WriteToUnix([]byte("DEST"), laddr); err != nil {
		t.Fatal(err)
	}
	_ = o.Stream.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "DEST" {
		t.Fatalf("read %q want DEST", buf[:n])
	}
}

func TestUnixgramConnReadDoesNotHangOnEOF(t *testing.T) {
	c, err := listenUnixgramUnbound(parse.Spec{Type: "UNIX-SENDTO"})
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
