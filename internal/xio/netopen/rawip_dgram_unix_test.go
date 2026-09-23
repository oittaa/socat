//go:build linux || darwin

package netopen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
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

// dialLoopbackRawIP4 binds a loopback source. 127.1.0.1 is used when the
// host accepts it; otherwise the assigned loopback address is used.
func dialLoopbackRawIP4(t *testing.T, proto int, dst net.IP) (*net.IPConn, net.IP) {
	t.Helper()
	var last error
	for _, src := range []net.IP{net.IPv4(127, 1, 0, 1), net.IPv4(127, 0, 0, 1)} {
		c, err := net.DialIP(fmt.Sprintf("ip4:%d", proto), &net.IPAddr{IP: src}, &net.IPAddr{IP: dst})
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c, src
		}
		skipIfRawIPPermissionDenied(t, err)
		if !errors.Is(err, syscall.EADDRNOTAVAIL) {
			t.Fatal(err)
		}
		last = err
	}
	t.Fatalf("dial raw IPv4: %v", last)
	return nil, nil
}

// rawPacketCarries reports whether got is the payload, or an IPv4 packet
// whose payload is that data.
func rawPacketCarries(got, payload []byte) bool {
	if bytes.Equal(got, payload) {
		return true
	}
	if len(got) < 20 || got[0]>>4 != 4 {
		return false
	}
	ihl := int(got[0]&0x0f) * 4
	if ihl < 20 || ihl > len(got) {
		return false
	}
	return bytes.Equal(got[ihl:], payload)
}

// readRawChildReply reads until a packet ends with want. A loopback socket
// with the same source and destination also receives the sent packet.
func readRawChildReply(t *testing.T, client *net.IPConn, sent []byte, want string) []byte {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	var got []byte
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("child reply=%q want %q", got, want)
		}
		var err error
		got, err = readRawDeadline(t, client, remaining)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.HasSuffix(got, []byte(want)) {
			return got
		}
		if rawPacketCarries(got, sent) {
			continue
		}
		t.Fatalf("child reply=%q want %q", got, want)
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ticker := time.NewTicker(testutil.PollInterval)
	defer ticker.Stop()
	sendRawPayload(t, client, payload)
	for {
		select {
		case got := <-gotCh:
			return got
		case err := <-errCh:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal("timed out waiting for raw IP payload")
		case <-ticker.C:
			sendRawPayload(t, client, payload)
		}
	}
}

func TestIP4DatagramAcceptsAnySender(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-DATAGRAM:127.0.0.1:%d,bind=127.0.0.1", rawIPTestProto))
	g := useGlobal()
	o, err := openIP4Datagram(ctx, mustAddr(t, spec), xio.ModeRDWR, g)
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	client, _ := dialLoopbackRawIP4(t, rawIPTestProto, net.IPv4(127, 0, 0, 1))
	payload := []byte("any-sender")
	got := waitRawRead(t, client, payload, o.Stream())
	if !rawPacketCarries(got, payload) {
		t.Fatalf("DATAGRAM read %q want %q", got, payload)
	}
}

func TestIP4RecvfromForkMaxChildrenZero(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECVFROM:%d,bind=127.0.0.1,fork,max-children=0", rawIPTestProto))
	_, err := openIP4Recvfrom(ctx, mustAddr(t, spec), xio.ModeRDWR, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err == nil {
		t.Fatal("expected max-children=0 to fail after bind")
	}
}

func TestIP4RecvfromForkChildPeerEnvironment(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECVFROM:%d,bind=127.0.0.1,fork", rawIPTestProto))
	g := useGlobal()
	g.Peer.PeerPort = "stale"
	o, err := openIP4Recvfrom(ctx, mustAddr(t, spec), xio.ModeRDWR, g)
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	right := parseChannel(t, `SYSTEM:echo $SOCAT_PEERADDR/$SOCAT_PEERPORT`)
	go func() { done <- runOpened(ctx, o, right, g) }()
	t.Cleanup(func() {
		_ = o.Close()
		<-done
	})

	client, src := dialLoopbackRawIP4(t, rawIPTestProto, net.IPv4(127, 0, 0, 1))
	want := src.String() + "/\n"
	sent := []byte("peer-env")
	sendRawPayload(t, client, sent)
	readRawChildReply(t, client, sent, want)
	if g.Peer.PeerPort != "stale" {
		t.Fatalf("parent peer port changed: %q", g.Peer.PeerPort)
	}
}

func TestIP4RecvWriteOnlyRejected(t *testing.T) {
	spec, ctx := openIP4Spec(t, fmt.Sprintf("IP4-RECV:%d,bind=127.0.0.1", rawIPTestProto))
	_, err := openIP4Recv(ctx, mustAddr(t, spec), xio.ModeWrite, useGlobal())
	skipIfRawIPPermissionDenied(t, err)
	if err == nil {
		t.Fatal("expected IP4-RECV write-only open to fail")
	}
	if err.Error() != "IP4-RECV is read-only" {
		t.Fatalf("err=%q want IP4-RECV is read-only", err)
	}
}
