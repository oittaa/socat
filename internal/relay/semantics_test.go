package relay

import (
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
