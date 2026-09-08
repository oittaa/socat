package dtlsopen

import (
	"bytes"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/relay"
)

type ambiguousPacket struct {
	net.PacketConn
	armed atomic.Bool
}

func (p *ambiguousPacket) WriteTo(data []byte, to net.Addr) (int, error) {
	n, err := p.PacketConn.WriteTo(data, to)
	if err == nil && n > 700 && p.armed.CompareAndSwap(true, false) {
		return n, kernelTooBig()
	}
	return n, err
}

func TestStreamDoesNotRetryAmbiguousTransportEMSGSIZE(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	transport := &ambiguousPacket{PacketConn: pc}
	client, server := streamDTLSPair(t, transport)
	stream := &streamConn{datagramConn: client}
	stream.ConfigureWritePeer(relay.ByteStreamIO)
	payload := bytes.Repeat([]byte("x"), 900)
	transport.armed.Store(true)
	n, err := stream.Write(payload)
	if n != 0 || !errors.Is(err, kernelTooBig().Err) {
		t.Errorf("ambiguous underlying send was retried: Write returned %d, %v; want error", n, err)
	}
	marker := []byte("end-marker")
	if _, err := client.Write(marker); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for i := 0; i < 10; i++ {
		buf := make([]byte, 2048)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(buf[:n], marker) {
			if !bytes.Equal(got, payload) {
				t.Fatalf("peer received %d application bytes for one %d-byte Write", len(got), len(payload))
			}
			return
		}
		got = append(got, buf[:n]...)
	}
	t.Fatal("marker not received")
}
