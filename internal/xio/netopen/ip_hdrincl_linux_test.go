//go:build linux

package netopen

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// TestRawIPHdrinclSendsPacketWithIPHeader proves IP_HDRINCL is not a no-op:
// the sender supplies a 20-byte IPv4 header, and IP4-RECV delivers the payload.
func TestRawIPHdrinclSendsPacketWithIPHeader(t *testing.T) {
	const proto = 253
	payload := []byte("hdrincl")

	recvSpec, err := parse.ParseSpec("IP4-RECV:253,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	recv, err := openIPRecvNetwork(ctx, recvSpec, xio.ModeRead, useGlobal(), "ip4", false)
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })

	sendSpec, err := parse.ParseSpec("IP4-SENDTO:127.0.0.1:253,ip-hdrincl,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	send, err := openIPSendtoNetwork(ctx, sendSpec, xio.ModeRDWR, useGlobal(), "ip4")
	skipIfRawIPPermissionDenied(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })

	pkt := ipv4HeaderInclPacket(net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), proto, payload)
	gotCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		n, rerr := recv.Stream.Read(buf)
		if rerr != nil {
			errCh <- rerr
			return
		}
		gotCh <- append([]byte(nil), buf[:n]...)
	}()
	if _, err := send.Stream.Write(pkt); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-gotCh:
		if string(got) != string(payload) {
			t.Fatalf("payload=%q want %q", got, payload)
		}
	case rerr := <-errCh:
		t.Fatal(rerr)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for IP_HDRINCL packet")
	}
}

func ipv4HeaderInclPacket(src, dst net.IP, proto int, payload []byte) []byte {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		panic("ipv4HeaderInclPacket requires IPv4 addresses")
	}
	hdr := make([]byte, 20+len(payload))
	hdr[0] = 0x45
	total := len(hdr)
	hdr[2] = byte(total >> 8)
	hdr[3] = byte(total)
	hdr[8] = 64
	hdr[9] = byte(proto)
	copy(hdr[12:16], src4)
	copy(hdr[16:20], dst4)
	copy(hdr[20:], payload)
	return hdr
}
