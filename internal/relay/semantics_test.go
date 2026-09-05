package relay

import (
	"bytes"
	"crypto/tls"
	"net"
	"os"
	"testing"
)

type semanticProbe struct {
	Stream
	readPeer, writePeer IOSemantics
}

func (*semanticProbe) IOSemantics() IOSemantics           { return MessageIO }
func (p *semanticProbe) ConfigureReadPeer(k IOSemantics)  { p.readPeer = k }
func (p *semanticProbe) ConfigureWritePeer(k IOSemantics) { p.writePeer = k }
func (p *semanticProbe) UnwrapStream() Stream             { return p.Stream }

func TestConfigureStreamPairUsesDirectionalCapabilities(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, reverse := range []bool{false, true} {
		p := &semanticProbe{}
		peer := FDStream{R: f, W: NetStream{Conn: &net.UDPConn{}}}
		if reverse {
			ConfigureStreamPair(peer, p)
		} else {
			ConfigureStreamPair(p, peer)
		}
		if p.readPeer != MessageIO || p.writePeer != ByteStreamIO {
			t.Fatalf("peer read/write = %v/%v", p.readPeer, p.writePeer)
		}
	}
}

func TestStreamSemanticsKnownAndUnknown(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	for _, tc := range []struct {
		name   string
		stream Stream
		want   IOSemantics
	}{
		{"pipe", FDStream{R: r, W: w}, ByteStreamIO},
		{"text", FDStream{R: bytes.NewReader(nil), W: &bytes.Buffer{}}, ByteStreamIO},
		{"tcp", NetStream{Conn: &net.TCPConn{}}, ByteStreamIO},
		{"tls", NetStream{Conn: tls.Client(nil, &tls.Config{MinVersion: tls.VersionTLS13})}, ByteStreamIO},
		{"udp", NetStream{Conn: &net.UDPConn{}}, MessageIO},
		{"unknown", RWCStream{}, UnknownIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r, w := StreamReadSemantics(tc.stream), StreamWriteSemantics(tc.stream); r != tc.want || w != tc.want {
				t.Fatalf("read/write = %v/%v", r, w)
			}
		})
	}
}

func TestAdaptationStopsZeroCopy(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "data")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	p := &semanticProbe{Stream: FDStream{R: f, W: f}}
	if _, ok := unwrapZeroCopyReader(p); ok {
		t.Fatal("zero-copy bypasses adapter")
	}
	if _, ok := unwrapZeroCopyWriter(p); ok {
		t.Fatal("zero-copy bypasses adapter")
	}
	if StreamReadFD(p) < 0 {
		t.Fatal("ordinary capability traversal lost the descriptor")
	}
}
