//go:build linux || darwin

package netopen

import (
	"context"
	"fmt"
	"io"
	"net"
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
