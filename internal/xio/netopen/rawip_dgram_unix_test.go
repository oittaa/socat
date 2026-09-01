//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

const rawIPTestProto = 254

func openIP4Spec(t *testing.T, spec string) (parse.Spec, context.Context) {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	return s, ctx
}

func dialRawIP4(t *testing.T, proto int, src, dst net.IP) *net.IPConn {
	t.Helper()
	c, err := net.DialIP(fmt.Sprintf("ip4:%d", proto), &net.IPAddr{IP: src}, &net.IPAddr{IP: dst})
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func sendRawPayload(t *testing.T, c *net.IPConn, payload []byte) {
	t.Helper()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
}

func readRawDeadline(t *testing.T, r io.Reader, timeout time.Duration) ([]byte, error) {
	t.Helper()
	if d, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(timeout))
	}
	buf := make([]byte, 256)
	n, err := r.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func waitRawRead(t *testing.T, client *net.IPConn, payload []byte, r io.Reader) []byte {
	t.Helper()
	gotCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		got, err := readRawDeadline(t, r, 4*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		gotCh <- got
	}()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case got := <-gotCh:
			return got
		case err := <-errCh:
			t.Fatal(err)
		default:
			sendRawPayload(t, client, payload)
			time.Sleep(20 * time.Millisecond)
		}
	}
	select {
	case got := <-gotCh:
		return got
	case err := <-errCh:
		t.Fatal(err)
	default:
		t.Fatal("timed out waiting for raw IP payload")
	}
	return nil
}

func TestIP4DatagramAcceptsAnySender(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-DATAGRAM:127.0.0.1:%d,bind=127.0.0.1", rawIPTestProto))
	g := useGlobal()
	o, err := openIP4Datagram(ctx, spec, xio.ModeRDWR, g)
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	client := dialRawIP4(t, rawIPTestProto, net.IPv4(127, 1, 0, 1), net.IPv4(127, 0, 0, 1))
	payload := []byte("any-sender")
	got := waitRawRead(t, client, payload, o.Stream)
	if string(got) != string(payload) {
		t.Fatalf("DATAGRAM read %q want %q", got, payload)
	}
}

func TestIP4DatagramRangeFilter(t *testing.T) {
	deniedSpec, deniedCtx := openIP4Spec(t, fmt.Sprintf("IP4-DATAGRAM:127.0.0.1:%d,bind=127.0.0.1,range=10.0.0.0/8", rawIPTestProto))
	denied, err := openIP4Datagram(deniedCtx, deniedSpec, xio.ModeRDWR, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = denied.Close() })

	client := dialRawIP4(t, rawIPTestProto, net.IPv4(127, 1, 0, 1), net.IPv4(127, 0, 0, 1))
	sendRawPayload(t, client, []byte("nope"))
	if _, err := readRawDeadline(t, denied.Stream, 200*time.Millisecond); err == nil {
		t.Fatal("range=10.0.0.0/8 accepted a 127.1.0.1 sender")
	}

	okSpec, okCtx := openIP4Spec(t, fmt.Sprintf("IP4-DATAGRAM:127.0.0.1:%d,bind=127.0.0.1,range=127.0.0.0/8", rawIPTestProto))
	allowed, err := openIP4Datagram(okCtx, okSpec, xio.ModeRDWR, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = allowed.Close() })
	got := waitRawRead(t, client, []byte("ok-range"), allowed.Stream)
	if string(got) != "ok-range" {
		t.Fatalf("range=127.0.0.0/8 got %q", got)
	}
}

func TestIP4DatagramTCPWrapFilter(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "hosts.allow")
	deny := filepath.Join(dir, "hosts.deny")
	if err := os.WriteFile(allow, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, ctx := openIP4Spec(t, fmt.Sprintf(
		"IP4-DATAGRAM:127.0.0.1:%d,bind=127.0.0.1,hosts-allow=%s,hosts-deny=%s",
		rawIPTestProto, allow, deny,
	))
	o, err := openIP4Datagram(ctx, spec, xio.ModeRDWR, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	client := dialRawIP4(t, rawIPTestProto, net.IPv4(127, 1, 0, 1), net.IPv4(127, 0, 0, 1))
	sendRawPayload(t, client, []byte("wrapped"))
	if _, err := readRawDeadline(t, o.Stream, 200*time.Millisecond); err == nil {
		t.Fatal("tcpwrap deny ALL accepted a packet")
	}
}

func TestIP4RecvfromNonForkOneShotAndPeerAddr(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECVFROM:%d,bind=127.0.0.1", rawIPTestProto))
	g := useGlobal()
	opened := make(chan *xio.Opened, 1)
	errc := make(chan error, 1)
	go func() {
		o, err := openIP4Recvfrom(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			errc <- err
			return
		}
		opened <- o
	}()

	client := dialRawIP4(t, rawIPTestProto, net.IPv4(127, 1, 0, 1), net.IPv4(127, 0, 0, 1))
	payload := []byte("oneshot")
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var o *xio.Opened
	for o == nil {
		select {
		case <-ticker.C:
			sendRawPayload(t, client, payload)
		case err := <-errc:
			skipIfRawIPPermissionDenied(t, err)
			t.Fatal(err)
		case o = <-opened:
		case <-ctx.Done():
			t.Fatal("timed out opening IP4-RECVFROM")
		}
	}
	t.Cleanup(func() { _ = o.Close() })
	if g.PeerAddr != "127.1.0.1" {
		t.Fatalf("SOCAT_PEERADDR=%q want 127.1.0.1", g.PeerAddr)
	}
	got, err := readRawDeadline(t, o.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("first read %q want %q", got, payload)
	}
	n, err := o.Stream.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("second read n=%d err=%v want EOF", n, err)
	}
}

func TestIP4RecvfromForkSessionsAndMaxChildren(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECVFROM:%d,bind=127.0.0.1,fork,max-children=2,readbytes=4", rawIPTestProto))
	o, err := openIP4Recvfrom(ctx, spec, xio.ModeRDWR, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindListen || o.Listener == nil {
		t.Fatalf("Kind=%v listener=%v want KindListen", o.Kind, o.Listener)
	}
	if o.MaxChildren != 2 {
		t.Fatalf("MaxChildren=%d want 2", o.MaxChildren)
	}
	if o.PeerFilter != nil {
		t.Fatal("IP-RECVFROM,fork must filter in Accept only")
	}
	assertWrapDialReadbytes(t, o)

	firstCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := o.Listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		firstCh <- c
	}()
	client := dialRawIP4(t, rawIPTestProto, net.IPv4(127, 1, 0, 1), net.IPv4(127, 0, 0, 1))
	payload := []byte("fork1")
	deadline := time.Now().Add(4 * time.Second)
	var first net.Conn
	for first == nil && time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatal(err)
		case first = <-firstCh:
		default:
			sendRawPayload(t, client, payload)
			time.Sleep(20 * time.Millisecond)
		}
	}
	if first == nil {
		t.Fatal("timed out accepting first RECVFROM fork session")
	}
	t.Cleanup(func() { _ = first.Close() })
	if ra, ok := first.RemoteAddr().(*net.IPAddr); !ok || ra.IP.String() != "127.1.0.1" {
		t.Fatalf("RemoteAddr=%v want 127.1.0.1", first.RemoteAddr())
	}
	buf := make([]byte, 16)
	n, err := first.Read(buf)
	if err != nil || string(buf[:n]) != "fork1" {
		t.Fatalf("first session n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = first.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("first session trailing n=%d err=%v want EOF", n, err)
	}

	secondCh := make(chan net.Conn, 1)
	go func() {
		c, err := o.Listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		secondCh <- c
	}()
	peer2 := dialRawIP4(t, rawIPTestProto, net.IPv4(127, 2, 0, 1), net.IPv4(127, 0, 0, 1))
	payload2 := []byte("fork2")
	var second net.Conn
	deadline = time.Now().Add(4 * time.Second)
	for second == nil && time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatal(err)
		case second = <-secondCh:
		default:
			sendRawPayload(t, peer2, payload2)
			time.Sleep(20 * time.Millisecond)
		}
	}
	if second == nil {
		t.Fatal("timed out accepting second RECVFROM fork session")
	}
	t.Cleanup(func() { _ = second.Close() })
	if ra, ok := second.RemoteAddr().(*net.IPAddr); !ok || ra.IP.String() != "127.2.0.1" {
		t.Fatalf("second RemoteAddr=%v want 127.2.0.1", second.RemoteAddr())
	}
	n, err = second.Read(buf)
	if err != nil || string(buf[:n]) != "fork2" {
		t.Fatalf("second session n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestIP4RecvfromForkMaxChildrenZero(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECVFROM:%d,bind=127.0.0.1,fork,max-children=0", rawIPTestProto))
	_, err := openIP4Recvfrom(ctx, spec, xio.ModeRDWR, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err == nil {
		t.Fatal("expected max-children=0 to fail after bind")
	}
}

func TestIP4RecvWriteOnlyRejected(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECV:%d,bind=127.0.0.1", rawIPTestProto))
	_, err := openIP4Recv(ctx, spec, xio.ModeWrite, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err == nil {
		t.Fatal("expected IP4-RECV write-only open to fail")
	}
	if err.Error() != "IP4-RECV is read-only" {
		t.Fatalf("err=%q want IP4-RECV is read-only", err)
	}
}
