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
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestUnixRecvfromForkHasWrapDial(t *testing.T) {
	path := unixSocketTestPath(t, "recv.sock")
	g := xio.NewSession(xio.Options{BlockSize: 8192}, logx.New())
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.PeerFilter() != nil {
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
	o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Listener() == nil || o.WrapDial() == nil {
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
	ch := startUDPAccept(o.Listener())
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	child := waitUDPAccept(t, ch, 2*time.Second, "unix recvfrom child")
	st, err := o.WrapDial()(child)
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
	u := &unixRecvStream{first: newFirstPacket([]byte("abcd")), from: true}
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
	u := &unixRecvStream{first: newFirstPacket(nil), from: true}
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

func requireUNIXDatagram(t *testing.T) {
	t.Helper()
	if !xio.FeatureUNIXDatagram {
		t.Skip("UNIX datagram not enabled")
	}
}

func waitUnixBindPath(t *testing.T, path string, errc <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := testutil.Until(ctx, func() (bool, error) {
		select {
		case err := <-errc:
			return false, err
		default:
		}
		_, err := os.Lstat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}); err != nil {
		t.Fatal(err)
	}
}

func unixgramClient(t *testing.T) *net.UnixConn {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unixSocketTestPath(t, "client.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func writeUnixgramTo(t *testing.T, c *net.UnixConn, path string, payload []byte) {
	t.Helper()
	if _, err := c.WriteToUnix(payload, &net.UnixAddr{Name: path, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}
}

func openUnixRecvfromAfter(t *testing.T, extra string, send func(*net.UnixConn, string)) (*xio.Opened, *net.UnixConn) {
	t.Helper()
	requireUNIXDatagram(t)
	path := unixSocketTestPath(t, "recv.sock")
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early" + extra)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	opened := make(chan *xio.Opened, 1)
	go func() {
		o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
		if err != nil {
			errc <- err
			return
		}
		opened <- o
	}()
	waitUnixBindPath(t, path, errc)
	client := unixgramClient(t)
	send(client, path)
	select {
	case err := <-errc:
		t.Fatal(err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		return o, client
	case <-time.After(3 * time.Second):
		t.Fatal("UNIX-RECVFROM did not receive")
	}
	return nil, nil
}

func openUnixRecvfromFork(t *testing.T, extra string) (*xio.Opened, string) {
	t.Helper()
	requireUNIXDatagram(t)
	path := unixSocketTestPath(t, "recv.sock")
	spec, err := parse.ParseSpec("UNIX-RECVFROM:" + path + ",unlink-early,fork" + extra)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUnixRecvfrom(context.Background(), mustAddr(t, spec), xio.ModeRDWR, xio.NewSession(xio.Options{BlockSize: 8192}, logx.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Listener() == nil {
		t.Fatal("UNIX-RECVFROM,fork did not return a listener")
	}
	return o, path
}

func TestUnixRecvfromNonForkSkipsEmptyUnlessNullEOF(t *testing.T) {
	o, _ := openUnixRecvfromAfter(t, "", func(client *net.UnixConn, path string) {
		writeUnixgramTo(t, client, path, nil)
		writeUnixgramTo(t, client, path, []byte("payload"))
	})
	got, err := readStreamTimeout(t, o.Stream(), 2*time.Second)
	if err != nil || got != "payload" {
		t.Fatalf("got %q err=%v want payload", got, err)
	}
	got, err = readStreamTimeout(t, o.Stream(), 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second=%q err=%v want EOF", got, err)
	}
}

func TestUnixRecvfromNonForkNullEOFEmptyEndsSession(t *testing.T) {
	o, _ := openUnixRecvfromAfter(t, ",null-eof", func(client *net.UnixConn, path string) {
		writeUnixgramTo(t, client, path, nil)
	})
	got, err := readStreamTimeout(t, o.Stream(), 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("empty null-eof got %q err=%v want EOF", got, err)
	}
}

func TestUnixRecvfromNonForkReplyDest(t *testing.T) {
	o, client := openUnixRecvfromAfter(t, "", func(client *net.UnixConn, path string) {
		writeUnixgramTo(t, client, path, []byte("ping"))
	})
	got, err := readStreamTimeout(t, o.Stream(), 2*time.Second)
	if err != nil || got != "ping" {
		t.Fatalf("got %q err=%v want ping", got, err)
	}
	if _, err := o.Stream().Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	got, err = readStreamTimeout(t, client, 2*time.Second)
	if err != nil || got != "pong" {
		t.Fatalf("reply %q err=%v want pong", got, err)
	}
}

func TestUnixRecvfromForkChildReplyCloseIsolation(t *testing.T) {
	o, path := openUnixRecvfromFork(t, "")
	clientA := unixgramClient(t)
	ch := startUDPAccept(o.Listener())
	writeUnixgramTo(t, clientA, path, []byte("ping"))
	child := waitUDPAccept(t, ch, 2*time.Second, "first unix recvfrom child")
	if _, ok := child.(*oneshotForkConn); !ok {
		t.Fatalf("child %T, want oneshotForkConn", child)
	}
	got, err := readStreamTimeout(t, child, 2*time.Second)
	if err != nil || got != "ping" {
		t.Fatalf("first %q err=%v want ping", got, err)
	}
	got, err = readStreamTimeout(t, child, 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("oneshot second=%q err=%v want EOF", got, err)
	}
	if _, err := child.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	got, err = readStreamTimeout(t, clientA, 2*time.Second)
	if err != nil || got != "pong" {
		t.Fatalf("reply %q err=%v want pong", got, err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}

	clientB := unixgramClient(t)
	ch = startUDPAccept(o.Listener())
	writeUnixgramTo(t, clientB, path, []byte("next"))
	child2 := waitUDPAccept(t, ch, 2*time.Second, "second unix recvfrom child")
	t.Cleanup(func() { _ = child2.Close() })
	got, err = readStreamTimeout(t, child2, 2*time.Second)
	if err != nil || got != "next" {
		t.Fatalf("after child close %q err=%v want next", got, err)
	}
}

func TestUnixRecvfromForkSkipsEmptyUnlessNullEOF(t *testing.T) {
	o, path := openUnixRecvfromFork(t, "")
	client := unixgramClient(t)
	ch := startUDPAccept(o.Listener())
	writeUnixgramTo(t, client, path, nil)
	writeUnixgramTo(t, client, path, []byte("payload"))
	child := waitUDPAccept(t, ch, 2*time.Second, "unix recvfrom after empty")
	t.Cleanup(func() { _ = child.Close() })
	got, err := readStreamTimeout(t, child, 2*time.Second)
	if err != nil || got != "payload" {
		t.Fatalf("got %q err=%v want payload", got, err)
	}
}

func TestUnixRecvfromForkNullEOFEmptyEndsSession(t *testing.T) {
	o, path := openUnixRecvfromFork(t, ",null-eof")
	client := unixgramClient(t)
	ch := startUDPAccept(o.Listener())
	writeUnixgramTo(t, client, path, nil)
	child := waitUDPAccept(t, ch, 2*time.Second, "unix recvfrom null-eof")
	t.Cleanup(func() { _ = child.Close() })
	got, err := readStreamTimeout(t, child, 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("empty null-eof got %q err=%v want EOF", got, err)
	}
}
