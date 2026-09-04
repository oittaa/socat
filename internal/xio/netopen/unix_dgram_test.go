//go:build linux || darwin

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

func TestUnixRecvfromSkipsEmptyUnlessNullEOF(t *testing.T) {
	path := unixSocketTestPath(t, "recv-empty.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct {
		o   *xio.Opened
		err error
	}, 1)
	go func() {
		o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, g)
		opened <- struct {
			o   *xio.Opened
			err error
		}{o, err}
	}()
	time.Sleep(40 * time.Millisecond)
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer-empty.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	dst := &net.UnixAddr{Name: path, Net: "unixgram"}
	if _, err := peer.WriteToUnix(nil, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUnix([]byte("payload"), dst); err != nil {
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
		if err != nil || string(buf[:n]) != "payload" {
			t.Fatalf("n=%d err=%v data=%q want payload", n, err, buf[:n])
		}
		n, err = result.o.Stream.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("trailing n=%d err=%v want EOF", n, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UNIX-RECVFROM did not skip the empty datagram")
	}
}

func TestUnixRecvfromNullEOFEmptyEndsSession(t *testing.T) {
	path := unixSocketTestPath(t, "recv-nulleof.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,null-eof")
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct {
		o   *xio.Opened
		err error
	}, 1)
	go func() {
		o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, g)
		opened <- struct {
			o   *xio.Opened
			err error
		}{o, err}
	}()
	time.Sleep(40 * time.Millisecond)
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer-nulleof.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.WriteToUnix(nil, &net.UnixAddr{Name: path, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatal(result.err)
		}
		t.Cleanup(func() { _ = result.o.Close() })
		n, err := result.o.Stream.Read(make([]byte, 16))
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("n=%d err=%v want EOF", n, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UNIX-RECVFROM,null-eof did not complete on empty datagram")
	}
}

func TestUnixRecvfromForkSkipsEmptyUnlessNullEOF(t *testing.T) {
	path := unixSocketTestPath(t, "recv-fork-empty.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer-fork-empty.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	accepted := make(chan net.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := o.Listener.Accept()
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()
	dst := &net.UnixAddr{Name: path, Net: "unixgram"}
	if _, err := peer.WriteToUnix(nil, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUnix([]byte("payload"), dst); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		t.Fatal(err)
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != "payload" {
			t.Fatalf("n=%d err=%v data=%q want payload", n, err, buf[:n])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UNIX-RECVFROM,fork did not skip the empty datagram")
	}
}

func TestUnixConnectDatagramEmptyIsEOF(t *testing.T) {
	serverPath := unixSocketTestPath(t, "dgram-eof-srv.sock")
	clientPath := unixSocketTestPath(t, "dgram-eof-cli.sock")
	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: serverPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UNIX-CONNECT:%s,socktype=%d,bind=%s,unlink-early", serverPath, unix.SOCK_DGRAM, clientPath))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if _, err := srv.WriteToUnix(nil, &net.UnixAddr{Name: clientPath, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}
	if d, ok := o.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	n, err := o.Stream.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("explicit unixgram n=%d err=%v want EOF", n, err)
	}
}

func TestUnixClientAutodetectDatagramEmptyIsNotEOF(t *testing.T) {
	serverPath := unixSocketTestPath(t, "dgram-auto-srv.sock")
	clientPath := unixSocketTestPath(t, "dgram-auto-cli.sock")
	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: serverPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	spec, err := parse.ParseSpec("UNIX-CLIENT:" + serverPath + ",bind=" + clientPath + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixConnect(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if _, err := srv.WriteToUnix(nil, &net.UnixAddr{Name: clientPath, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}
	if d, ok := o.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	n, err := o.Stream.Read(make([]byte, 8))
	if errors.Is(err, io.EOF) {
		t.Fatal("autodetect unixgram empty packet must not be EOF")
	}
	if n != 0 || err != nil {
		t.Fatalf("autodetect unixgram n=%d err=%v want 0, nil", n, err)
	}
}

func TestUnixRecvfromCanceledWhileWaiting(t *testing.T) {
	path := unixSocketTestPath(t, "recv-cancel.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		_, err := openUnixRecvfrom(ctx, spec, xio.ModeRDWR, g)
		done <- err
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("openUnixRecvfrom error=%v want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UNIX-RECVFROM ignored context cancellation")
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

func TestUnixRecvStreamEmptyFirstIsEOF(t *testing.T) {
	u := &unixRecvStream{from: true, firstEOF: true}
	n, err := u.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty first n=%d err=%v want EOF", n, err)
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

func TestUnixRecvAppendFcntlOnce(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	spec, err := parse.ParseSpec("UNIX-RECV:/tmp/x,append")
	if err != nil {
		t.Fatal(err)
	}
	c, err := listenUnixgramUnbound(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	if err := applyUnixgramSocketOptions(c, spec); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, op := range ops {
		if op == "F_SETFL" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("F_SETFL count=%d want 1 (ops=%v)", n, ops)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var ferr error
	if err := raw.Control(func(fd uintptr) {
		flags, ferr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if ferr != nil {
		t.Fatal(ferr)
	}
	if flags&unix.O_APPEND == 0 {
		t.Fatal("UNIX-RECV append did not set O_APPEND")
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
	if got := packetSockoptInt(t, c, unix.SO_KEEPALIVE); got == 0 {
		// Darwin getsockopt returns the so_options bit (8), not 1.
		t.Fatalf("SO_KEEPALIVE=%d want enabled", got)
	}
}

func TestUnixRecvStreamSetupStreamSetsockoptUnix(t *testing.T) {
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
	if _, err := xio.SetupStream(spec, &unixRecvStream{c: c}); err != nil {
		t.Fatalf("SetupStream on UNIX-RECV wrapper must not fail: %v", err)
	}
	if got := packetSockoptInt(t, c, unix.SO_KEEPALIVE); got == 0 {
		t.Fatalf("SO_KEEPALIVE=%d want enabled after SetupStream", got)
	}
}

func TestUnixgramListenPastSocketThenPrebindUnix(t *testing.T) {
	path := unixSocketTestPath(t, "phase.sock")
	spec, err := parse.ParseSpec(fmt.Sprintf(
		"UNIX-RECV:%s,setsockopt-socket=%d:%d:1,setsockopt-listen=%d:%d:0",
		path, unix.SOL_SOCKET, unix.SO_KEEPALIVE, unix.SOL_SOCKET, unix.SO_KEEPALIVE,
	))
	if err != nil {
		t.Fatal(err)
	}
	var values []int
	restore := xio.SetSockoptTestHook(func(c xio.SockoptCall) {
		if c.Opt == unix.SO_KEEPALIVE {
			values = append(values, c.IntValue)
		}
	})
	defer restore()
	c, err := listenUnixgramBound(spec, &net.UnixAddr{Name: path, Net: "unixgram"}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if len(values) != 2 || values[0] != 1 || values[1] != 0 {
		t.Fatalf("SO_KEEPALIVE values=%v want PASTSOCKET 1 then PREBIND 0", values)
	}
}

func TestUnixgramConnCanceledReadDoesNotMutateReusedBuffer(t *testing.T) {
	local := unixSocketTestPath(t, "local.sock")
	c, err := listenUnixgramBound(parse.Spec{Type: "UNIX-DATAGRAM"}, &net.UnixAddr{Name: local, Net: "unixgram"}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "peer.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := &unixgramConn{
		UnixConn:   c,
		raddr:      &net.UnixAddr{Name: "unused", Net: "unixgram"},
		filterPeer: false,
		ctx:        ctx,
	}

	buf := make([]byte, 32)
	copy(buf, "caller-buffer")
	done := make(chan error, 1)
	go func() {
		_, err := u.Read(buf)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Read error=%v want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled Read did not return")
	}

	const sentinel byte = 0xa5
	for i := range buf {
		buf[i] = sentinel
	}
	if _, err := peer.WriteToUnix([]byte("late-datagram"), &net.UnixAddr{Name: local, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		for i, b := range buf {
			if b != sentinel {
				t.Fatalf("abandoned receive mutated reused caller buffer at %d: %q", i, buf)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestUnixDatagramOpensWithoutDestination(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	remote := unixSocketTestPath(t, "late.sock")
	spec, err := parse.ParseSpec("UNIX-DATAGRAM:" + remote + ",forever,interval=0.2")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	o, err := openUnixDatagram(ctx, spec, xio.ModeWrite, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if elapsed > 500*time.Millisecond {
		t.Fatalf("DATAGRAM open waited %s for a missing destination", elapsed)
	}
}

func TestUnixDatagramWriteReachesConfiguredDestination(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	dest := unixSocketTestPath(t, "dest.sock")
	spec, err := parse.ParseSpec("UNIX-DATAGRAM:" + dest)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixDatagram(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	recv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: dest, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	if _, err := o.Stream.Write([]byte("dest-write")); err != nil {
		t.Fatal(err)
	}
	_ = recv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := recv.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "dest-write" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestUnixDatagramAcceptsNamedWrongPeer(t *testing.T) {
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

	spec, err := parse.ParseSpec("UNIX-DATAGRAM:" + dest + ",bind=" + local)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixDatagram(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	laddr := &net.UnixAddr{Name: local, Net: "unixgram"}
	if _, err := wrongConn.WriteToUnix([]byte("NAMED-WRONG\n"), laddr); err != nil {
		t.Fatal(err)
	}

	_ = o.Stream.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "NAMED-WRONG\n" {
		t.Fatalf("read %q want NAMED-WRONG (UNIX-DATAGRAM must accept any sender)", buf[:n])
	}
}

func TestUnixDatagramReceivesMultipleDatagrams(t *testing.T) {
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

	spec, err := parse.ParseSpec("UNIX-DATAGRAM:" + dest + ",bind=" + local)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixDatagram(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	laddr := &net.UnixAddr{Name: local, Net: "unixgram"}
	if _, err := destConn.WriteToUnix([]byte("one"), laddr); err != nil {
		t.Fatal(err)
	}
	if _, err := destConn.WriteToUnix([]byte("two"), laddr); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	got := make([]string, 0, 2)
	buf := make([]byte, 8)
	for len(got) < 2 {
		_ = o.Stream.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(deadline)
		n, err := o.Stream.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", len(got), err)
		}
		got = append(got, string(buf[:n]))
	}
	if got[0] != "one" || got[1] != "two" {
		t.Fatalf("got %q want [one two] (UNIX-DATAGRAM is persistent, not one-shot)", got)
	}
}
