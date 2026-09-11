//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

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

func TestUnixRecvfromForkHasWrapDial(t *testing.T) {
	path := unixSocketTestPath(t, "recv.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.PeerFilter != nil {
		t.Fatal("UNIX-RECVFROM must not install an IP PeerFilter")
	}
	assertWrapDialReadbytes(t, o)
}

func TestUnixRecvfromForkWrapAfterLifecycle(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	path := unixSocketTestPath(t, "recv-life.sock")
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) {
		ops = append(ops, op)
	})
	t.Cleanup(restore)
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,append")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Listener == nil || o.WrapDial == nil {
		t.Fatal("UNIX-RECVFROM,fork did not return a wrapable listener")
	}
	if len(ops) == 0 {
		t.Fatal("lifecycle option was not applied on the unixgram socket")
	}
	applied := append([]string(nil), ops...)

	client, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ch := startUDPAccept(o.Listener)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	child := waitUDPAccept(t, ch, 2*time.Second, "unix recvfrom child")
	st, err := o.WrapDial(child)
	if err != nil {
		t.Fatalf("WrapDial after lifecycle on owner: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if fmt.Sprint(ops) != fmt.Sprint(applied) {
		t.Fatalf("WrapDial re-applied lifecycle: before %v after %v", applied, ops)
	}
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q err=%v want hello", got, err)
	}
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

func TestUnixRecvfromForkSetupFailureUnlinksBind(t *testing.T) {
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
	path := unixSocketTestPath(t, "recv.sock")
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,max-children=0")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
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
	o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, nil)
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
	o, err := openUnixRecv(context.Background(), mustAddr(t, spec), xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if xio.RegisteredUnlinkCount() != before {
		t.Fatal("abstract UNIX-RECV registered a filesystem unlink")
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
	if err := applyUnixgramSocketOptions(c, mustAddr(t, spec)); err != nil {
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
	if _, err := xio.SetupStream(mustAddr(t, spec), &unixRecvStream{c: c}); err != nil {
		t.Fatalf("SetupStream on UNIX-RECV wrapper must not fail: %v", err)
	}
	if got := packetSockoptInt(t, c, unix.SO_KEEPALIVE); got == 0 {
		t.Fatalf("SO_KEEPALIVE=%d want enabled after SetupStream", got)
	}
}
