package dtlsopen

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/relay"
)

type packetTestConn struct {
	net.Conn
	limit          int
	incoming, sent [][]byte
	reads          int
	write          func([]byte) (int, error)
}

func (c *packetTestConn) MaxDatagramSize() int { return c.limit }
func (c *packetTestConn) CloseWrite() error    { return nil }
func (c *packetTestConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.incoming) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.incoming[0])
	c.incoming = c.incoming[1:]
	return n, nil
}
func (c *packetTestConn) Write(p []byte) (int, error) {
	if c.write != nil {
		return c.write(p)
	}
	if len(p) > c.limit {
		return 0, dtls13.ErrDatagramTooLarge
	}
	c.sent = append(c.sent, bytes.Clone(p))
	return len(p), nil
}

type semanticTestStream struct {
	relay.Stream
	kind relay.IOSemantics
}

func (s semanticTestStream) IOSemantics() relay.IOSemantics { return s.kind }
func (s semanticTestStream) StreamProps() relay.Props {
	p := relay.NoProps()
	if s.Stream != nil {
		p = s.Stream.StreamProps()
	}
	p.ReadIO, p.WriteIO = s.kind, s.kind
	return p
}

func TestPacketizerDTLSPairStaysStrict(t *testing.T) {
	a := &streamConn{datagramConn: &packetTestConn{limit: 4}}
	b := &streamConn{datagramConn: &packetTestConn{limit: 4}}
	relay.ConfigureStreamPair(relay.NetStream{Conn: a}, relay.NetStream{Conn: b})
	for _, c := range []*streamConn{a, b} {
		if n, err := c.Write([]byte("large")); n != 0 || !errors.Is(err, dtls13.ErrDatagramTooLarge) {
			t.Fatalf("DTLS pair write = %d, %v", n, err)
		}
	}
}

func TestPacketizerFittingWritesRemainSeparate(t *testing.T) {
	inner := &packetTestConn{limit: 1200}
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	for _, size := range []int{200, 1200, 0, 1} {
		if n, err := c.Write(bytes.Repeat([]byte{'x'}, size)); n != size || err != nil {
			t.Fatalf("write = %d, %v", n, err)
		}
	}
	if len(inner.sent) != 4 {
		t.Fatalf("records = %d", len(inner.sent))
	}
	for i, size := range []int{200, 1200, 0, 1} {
		if len(inner.sent[i]) != size {
			t.Fatalf("record %d length = %d", i, len(inner.sent[i]))
		}
	}
}

func TestPacketizerDoesNotRetryUnchangedOverflow(t *testing.T) {
	inner := &packetTestConn{limit: 4}
	calls := 0
	inner.write = func([]byte) (int, error) { calls++; return 0, dtls13.ErrDatagramTooLarge }
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	if n, err := c.Write([]byte("abcdef")); n != 0 || !errors.Is(err, dtls13.ErrDatagramTooLarge) || calls != 1 {
		t.Fatalf("write = %d, %v; calls %d", n, err, calls)
	}
}

func TestPacketizerDoesNotRetryUnclassifiedEMSGSIZE(t *testing.T) {
	inner := &packetTestConn{limit: 4}
	calls := 0
	inner.write = func([]byte) (int, error) { calls++; inner.limit = 2; return 0, kernelTooBig() }
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	n, err := c.Write([]byte("abcdef"))
	if n != 0 || !errors.Is(err, kernelTooBig().Err) || errors.Is(err, dtls13.ErrDatagramTooLarge) || calls != 1 {
		t.Fatalf("write = %d, %v; calls %d", n, err, calls)
	}
}

func TestPacketizerDoesNotRetryPartialEMSGSIZE(t *testing.T) {
	inner := &packetTestConn{limit: 4}
	inner.write = func(p []byte) (int, error) {
		return 1, kernelTooBig()
	}
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	n, err := c.Write([]byte("abcdef"))
	if n != 1 || !errors.Is(err, kernelTooBig().Err) {
		t.Fatalf("partial write = %d, %v", n, err)
	}
}
