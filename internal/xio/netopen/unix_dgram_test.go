//go:build unix

package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestUnixPacketConnOneShotDoesNotReadParent(t *testing.T) {
	path := unixSocketTestPath(t, "recv.sock")
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	parent, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })

	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	other, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "other.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })

	if _, err := peer.WriteToUnix([]byte("first"), laddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, addr, err := parent.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}

	child := &unixPacketConn{
		c:      parent,
		peer:   addr,
		first:  append([]byte(nil), buf[:n]...),
		shared: true,
	}

	if _, err := other.WriteToUnix([]byte("second"), laddr); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 16)
	n, err = child.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != "first" {
		t.Fatalf("first read=%q", got[:n])
	}
	n, err = child.Read(got)
	if n != 0 || err != io.EOF {
		t.Fatalf("second child read n=%d err=%v want EOF", n, err)
	}

	_ = parent.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = parent.ReadFromUnix(got)
	if err != nil {
		t.Fatalf("parent lost the second datagram: %v", err)
	}
	if string(got[:n]) != "second" {
		t.Fatalf("parent read=%q want second", got[:n])
	}
}

func TestUnixPacketConnSetReadDeadlineDoesNotPoisonParent(t *testing.T) {
	path := unixSocketTestPath(t, "recv.sock")
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	parent, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })

	child := &unixPacketConn{c: parent, first: []byte("pkt"), shared: true}
	if err := child.SetReadDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.WriteToUnix([]byte("keep"), laddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, _, err := parent.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("parent read after child deadline: %v", err)
	}
	if string(buf[:n]) != "keep" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestUnixPacketConnSetWriteDeadlineDoesNotPoisonParent(t *testing.T) {
	path := unixSocketTestPath(t, "recv.sock")
	laddr := &net.UnixAddr{Name: path, Net: "unixgram"}
	parent, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })

	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	child := &unixPacketConn{c: parent, peer: peer.LocalAddr().(*net.UnixAddr), first: []byte("pkt"), shared: true}
	if err := child.SetWriteDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := child.Write([]byte("late")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write err=%v want deadline exceeded", err)
	}
	if _, err := peer.WriteToUnix([]byte("keep"), laddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, _, err := parent.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("parent read after child write deadline: %v", err)
	}
	if string(buf[:n]) != "keep" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestUnixPacketConnShortReadDropsRemainder(t *testing.T) {
	child := &unixPacketConn{first: []byte("abcd"), shared: true}
	buf := make([]byte, 1)
	n, err := child.Read(buf)
	if err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("short read n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = child.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("remainder n=%d err=%v want EOF", n, err)
	}
}

func TestUnixRecvfromWaitsForDatagramThenEOF(t *testing.T) {
	path := unixSocketTestPath(t, "recv.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}

	type openResult struct {
		o   *xio.Opened
		err error
	}
	opened := make(chan openResult, 1)
	go func() {
		o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, g)
		opened <- openResult{o: o, err: err}
	}()

	time.Sleep(30 * time.Millisecond)
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.WriteToUnix([]byte("hello"), &net.UnixAddr{Name: path, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatal(result.err)
		}
		t.Cleanup(func() { _ = result.o.Close() })
		buf := make([]byte, 16)
		n, err := result.o.Stream.Read(buf)
		if err != nil || string(buf[:n]) != "hello" {
			t.Fatalf("n=%d err=%v data=%q", n, err, buf[:n])
		}
		n, err = result.o.Stream.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("trailing n=%d err=%v want EOF", n, err)
		}
		if g.PeerAddr == "" {
			t.Fatal("expected SOCAT_PEERADDR to be set at open")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UNIX-RECVFROM open did not wait for the datagram")
	}
}

func TestUnixRecvfromForkHasWrapDial(t *testing.T) {
	path := unixSocketTestPath(t, "recv.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.PeerFilter != nil {
		t.Fatal("UNIX-RECVFROM must not install an IP PeerFilter")
	}
	assertWrapDialReadbytes(t, o)
}

func TestUnixRecvStreamShortReadDropsRemainder(t *testing.T) {
	u := &unixRecvStream{first: []byte("abcd"), from: true, firstEOF: true}
	buf := make([]byte, 1)
	n, err := u.Read(buf)
	if err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("short read n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = u.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("remainder n=%d err=%v want EOF", n, err)
	}
}

func TestUnixSendtoBindUnlinksOnSignalSweep(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	local := unixSocketTestPath(t, "local.sock")
	remote := unixSocketTestPath(t, "remote.sock")
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",bind=" + local)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if _, err := os.Lstat(local); err != nil {
		t.Fatalf("SENDTO bind path missing after open: %v", err)
	}
	if xio.RegisteredUnlinkCount() == 0 {
		t.Fatal("SENDTO bind path was not registered for signal-exit unlink")
	}
	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(local); !os.IsNotExist(err) {
		t.Fatalf("SENDTO bind path survived signal sweep: %v", err)
	}
}

func TestUnixSendtoBindUnlinksOnClose(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	local := unixSocketTestPath(t, "local.sock")
	remote := unixSocketTestPath(t, "remote.sock")
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",bind=" + local)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(local); err != nil {
		t.Fatalf("SENDTO bind path missing after open: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(local); !os.IsNotExist(err) {
		t.Fatalf("SENDTO bind path survived Close: %v", err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("Close left a signal-exit unlink registration")
	}
}

func TestUnixSendtoBindUnlinkCloseZeroKeepsPath(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	local := unixSocketTestPath(t, "local.sock")
	remote := unixSocketTestPath(t, "remote.sock")
	spec, err := parse.ParseSpec("UNIX-SENDTO:" + remote + ",bind=" + local + ",unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixSendto(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	if xio.RegisteredUnlinkCount() != 0 {
		t.Fatal("unlink-close=0 registered a signal-exit unlink")
	}
	xio.UnlinkRegisteredPaths()
	if _, err := os.Lstat(local); err != nil {
		t.Fatalf("unlink-close=0 bind path was removed on signal sweep: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(local); err != nil {
		t.Fatalf("unlink-close=0 bind path was removed on close: %v", err)
	}
}

func TestUnixRecvfromForkSetupFailureUnlinksBind(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	path := unixSocketTestPath(t, "recv.sock")
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,max-children=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected max-children=0 to fail after bind")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("RECVFROM bind path survived setup failure: %v", err)
	}
}

func TestUnixRecvfromForkSetupFailureUnlinkCloseZeroKeepsPath(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	path := unixSocketTestPath(t, "recv.sock")
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,max-children=0,unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("expected max-children=0 to fail after bind")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("unlink-close=0 bind path was removed on setup failure: %v", err)
	}
}

func TestUnixRecvAbstractDoesNotRegisterUnlink(t *testing.T) {
	if !xio.FeatureUNIXDatagram || !xio.FeatureABSTRACT {
		t.Skip("abstract UNIX datagram not enabled")
	}
	name := "@socat-abs-recv-unlink"
	spec, err := parse.ParseSpec("UNIX-RECV:" + name)
	if err != nil {
		t.Fatal(err)
	}
	before := xio.RegisteredUnlinkCount()
	o, err := openUnixRecv(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if xio.RegisteredUnlinkCount() != before {
		t.Fatal("abstract UNIX-RECV registered a filesystem unlink")
	}
}

func TestApplyUnixgramSocketOptionsAppliesLateUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux SO_SNDBUF doubling")
	}
	path := unixSocketTestPath(t, "late.sock")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyUnixgramSocketOptions(c, spec); err != nil {
		t.Fatal(err)
	}
	if got := packetSockoptInt(t, c, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after applyUnixgramSocketOptions", got)
	}
	if got := packetSockoptInt(t, c, unix.SO_RCVBUF); got < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after applyUnixgramSocketOptions", got)
	}
}

func TestApplyUnixgramSocketOptionsAppliesSetsockoptUnix(t *testing.T) {
	path := unixSocketTestPath(t, "sockopt.sock")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UNIX-RECVFROM:%s,setsockopt=%d:%d:1", path, unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyUnixgramSocketOptions(c, spec); err != nil {
		t.Fatalf("UNIX datagram setsockopt must apply, not no-op: %v", err)
	}
	if got := packetSockoptInt(t, c, unix.SO_KEEPALIVE); got != 1 {
		t.Fatalf("SO_KEEPALIVE=%d want 1", got)
	}
}

func TestUnixRecvStreamWrapCommonSetsockoptUnix(t *testing.T) {
	path := unixSocketTestPath(t, "wrap-sockopt.sock")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UNIX-RECV:%s,setsockopt=%d:%d:1", path, unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xio.WrapCommon(spec, &unixRecvStream{c: c}); err != nil {
		t.Fatalf("WrapCommon on UNIX-RECV wrapper must not fail: %v", err)
	}
	if got := packetSockoptInt(t, c, unix.SO_KEEPALIVE); got != 1 {
		t.Fatalf("SO_KEEPALIVE=%d want 1 after WrapCommon", got)
	}
}
