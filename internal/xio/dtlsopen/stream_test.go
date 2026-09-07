package dtlsopen

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/testcert"
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

func TestPacketizerSelectsPeerHalves(t *testing.T) {
	for _, tc := range []struct {
		name        string
		read, write relay.IOSemantics
	}{
		{"stream", relay.ByteStreamIO, relay.ByteStreamIO},
		{"messages", relay.MessageIO, relay.MessageIO},
		{"unknown", relay.UnknownIO, relay.UnknownIO},
		{"file-to-dtls-dtls-to-udp", relay.ByteStreamIO, relay.MessageIO},
		{"udp-to-dtls-dtls-to-file", relay.MessageIO, relay.ByteStreamIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &packetTestConn{limit: 4, incoming: [][]byte{[]byte("abcdef")}}
			c := &streamConn{datagramConn: inner}
			peer := relay.FDStream{R: semanticTestStream{kind: tc.read}, W: semanticTestStream{kind: tc.write}}
			relay.ConfigureStreamPair(relay.NetStream{Conn: c}, peer)
			n, err := c.Write([]byte("abcdefghij"))
			if tc.read == relay.ByteStreamIO {
				if n != 10 || err != nil || len(inner.sent) != 3 || !bytes.Equal(bytes.Join(inner.sent, nil), []byte("abcdefghij")) {
					t.Fatalf("packetized write = %d, %v, %q", n, err, inner.sent)
				}
			} else if n != 0 || !errors.Is(err, dtls13.ErrDatagramTooLarge) || len(inner.sent) != 0 {
				t.Fatalf("strict write = %d, %v, %q", n, err, inner.sent)
			}
			p := make([]byte, 3)
			if n, err := c.Read(p); n != 3 || err != nil || string(p) != "abc" {
				t.Fatalf("first read = %q, %d, %v", p, n, err)
			}
			n, err = c.Read(p)
			if tc.write == relay.ByteStreamIO {
				if n != 3 || err != nil || string(p) != "def" || inner.reads != 1 {
					t.Fatalf("remainder = %q, %d, %v; reads %d", p, n, err, inner.reads)
				}
			} else if n != 0 || err != io.EOF {
				t.Fatalf("strict read retained a tail: %d, %v", n, err)
			}
		})
	}
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

func TestPacketizerLargeIncomingRecordAndEmptyRead(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 1024)
	inner := &packetTestConn{limit: 200, incoming: [][]byte{data, []byte("next")}}
	c := &streamConn{datagramConn: inner}
	c.ConfigureReadPeer(relay.ByteStreamIO)
	for _, p := range [][]byte{nil, {}} {
		if n, err := c.Read(p); n != 0 || err != nil || inner.reads != 0 {
			t.Fatalf("empty read consumed data: %d, %v", n, err)
		}
	}
	got := make([]byte, len(data))
	for offset := 0; offset < len(got); {
		n, err := c.Read(got[offset:min(offset+73, len(got))])
		if err != nil || n == 0 {
			t.Fatalf("read = %d, %v", n, err)
		}
		offset += n
	}
	if !bytes.Equal(got, data) || inner.reads != 1 {
		t.Fatalf("incoming record truncated; reads = %d", inner.reads)
	}
	p := make([]byte, 8192)
	if n, err := c.Read(p); n != 4 || err != nil || string(p[:n]) != "next" {
		t.Fatalf("next = %d, %v", n, err)
	}
}

func TestPacketizerCapacityChangeAndInterruptedWrite(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "capacity-shrinks", true: "timeout-after-progress"}[fail], func(t *testing.T) {
			inner := &packetTestConn{limit: 4}
			calls := 0
			inner.write = func(p []byte) (int, error) {
				calls++
				if calls == 2 {
					if fail {
						return 0, os.ErrDeadlineExceeded
					}
					inner.limit = 2
					return 0, dtls13.ErrDatagramTooLarge
				}
				if len(p) > inner.limit {
					t.Fatalf("write exceeds changed limit: %d", len(p))
				}
				inner.sent = append(inner.sent, bytes.Clone(p))
				return len(p), nil
			}
			c := &streamConn{datagramConn: inner}
			c.ConfigureWritePeer(relay.ByteStreamIO)
			n, err := c.Write([]byte("abcdefghij"))
			if fail {
				if n != 4 || !errors.Is(err, os.ErrDeadlineExceeded) || calls != 2 {
					t.Fatalf("partial write = %d, %v; calls %d", n, err, calls)
				}
				if _, err := c.Write([]byte("abcdefghij")[n:]); err != nil {
					t.Fatal(err)
				}
			} else if n != 10 || err != nil {
				t.Fatalf("write = %d, %v", n, err)
			}
			if string(bytes.Join(inner.sent, nil)) != "abcdefghij" {
				t.Fatalf("lost or duplicated data: %q", inner.sent)
			}
		})
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

func TestPacketizerRecoversFromKernelEMSGSIZE(t *testing.T) {
	inner := &packetTestConn{limit: 4}
	calls := 0
	inner.write = func(p []byte) (int, error) {
		calls++
		if calls == 1 {
			inner.limit = 2
			return 0, kernelTooBig()
		}
		if len(p) > inner.limit {
			t.Fatalf("write exceeds changed limit: %d", len(p))
		}
		inner.sent = append(inner.sent, bytes.Clone(p))
		return len(p), nil
	}
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	n, err := c.Write([]byte("abcdef"))
	if n != 6 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	if string(bytes.Join(inner.sent, nil)) != "abcdef" {
		t.Fatalf("lost or duplicated data: %q", inner.sent)
	}
}

func TestPacketizerDoesNotRetryUnchangedEMSGSIZE(t *testing.T) {
	inner := &packetTestConn{limit: 4}
	calls := 0
	inner.write = func([]byte) (int, error) { calls++; return 0, kernelTooBig() }
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	n, err := c.Write([]byte("abcdef"))
	if n != 0 || !dtls13.IsMessageTooLong(err) || errors.Is(err, dtls13.ErrDatagramTooLarge) || calls != 1 {
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
	if n != 1 || !dtls13.IsMessageTooLong(err) {
		t.Fatalf("partial write = %d, %v", n, err)
	}
}

type limitedPacket struct {
	net.PacketConn
	mu    sync.Mutex
	limit int
}

func (c *limitedPacket) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	limit := c.limit
	c.mu.Unlock()
	if limit > 0 && len(p) > limit {
		return 0, kernelTooBig()
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *limitedPacket) setLimit(n int) {
	c.mu.Lock()
	c.limit = n
	c.mu.Unlock()
}

func streamDTLSPair(t *testing.T, clientPC net.PacketConn) (*dtls13.Conn, *dtls13.Conn) {
	t.Helper()
	ca, err := testcert.NewAuthority("stream PMTU CA")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := ca.Leaf("client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	clientCfg := &dtls13.Config{ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{clientCert.TLS()}}
	serverCfg := &dtls13.Config{Certificates: []tls.Certificate{serverCert.TLS()}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	lnUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lnUDP.Close() })
	listener, err := dtls13.Listen(lnUDP, serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client, err := dtls13.Client(ctx, clientPC, listener.Addr(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := peer.(*dtls13.Conn)
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func TestDatagramWriteSurfacesKernelEMSGSIZE(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	transport := &limitedPacket{PacketConn: pc}
	client, _ := streamDTLSPair(t, transport)
	before := client.MaxDatagramSize()
	if before <= 0 {
		t.Fatal("empty advertised budget")
	}
	transport.setLimit(600)
	n, err := client.Write(make([]byte, 900))
	if n != 0 || !dtls13.IsMessageTooLong(err) || errors.Is(err, dtls13.ErrDatagramTooLarge) {
		t.Fatalf("datagram write = %d, %v", n, err)
	}
	if client.MaxDatagramSize() >= before {
		t.Fatal("kernel EMSGSIZE did not shrink MaxDatagramSize")
	}
}

func TestStreamWriteRecoversFromKernelEMSGSIZE(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	transport := &limitedPacket{PacketConn: pc}
	client, server := streamDTLSPair(t, transport)
	before := client.MaxDatagramSize()
	if before < 900 {
		t.Fatalf("MaxDatagramSize %d", before)
	}
	stream := &streamConn{datagramConn: client}
	stream.ConfigureWritePeer(relay.ByteStreamIO)
	transport.setLimit(600)
	payload := bytes.Repeat([]byte("x"), 900)
	n, err := stream.Write(payload)
	if n != len(payload) || err != nil {
		t.Fatalf("stream write = %d, %v", n, err)
	}
	after := client.MaxDatagramSize()
	if after >= before {
		t.Fatalf("MaxDatagramSize stayed %d", after)
	}
	got := make([]byte, len(payload))
	if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	read := 0
	for read < len(got) {
		n, err := server.Read(got[read:])
		if err != nil {
			t.Fatalf("server read: %v after %d", err, read)
		}
		read += n
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: read %d", read)
	}
}

func TestPacketizerCloseInterruptsWrite(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	inner := &packetTestConn{Conn: a, limit: 4}
	started := make(chan struct{})
	inner.write = func(p []byte) (int, error) { close(started); return a.Write(p) }
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("abcdefgh")); done <- err }()
	<-started
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed write succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close blocked behind a write")
	}
}

func TestPacketizerConcurrentWritesKeepChunksTogether(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if err := a.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := b.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	inner := &packetTestConn{Conn: a, limit: 2}
	first := true
	inner.write = func(p []byte) (int, error) {
		if first {
			first = false
			close(started)
		}
		return a.Write(p)
	}
	c := &streamConn{datagramConn: inner}
	c.ConfigureWritePeer(relay.ByteStreamIO)
	done := make(chan error, 2)
	go func() { _, err := c.Write([]byte("aaaaaa")); done <- err }()
	<-started
	go func() { _, err := c.Write([]byte("bbbbbb")); done <- err }()
	p := make([]byte, 12)
	if _, err := io.ReadFull(b, p); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if string(p) != "aaaaaabbbbbb" {
		t.Fatalf("interleaved writes: %q", p)
	}
}

func TestPacketizerLineConversion(t *testing.T) {
	inner := &packetTestConn{limit: 64}
	stream, err := wrap(spec(t, "DTLS:localhost:4433,crnl,readbytes=16384,escape=255"))(inner)
	if err != nil {
		t.Fatal(err)
	}
	relay.ConfigureStreamPair(stream, semanticTestStream{kind: relay.ByteStreamIO})
	data := strings.Repeat("x", 8192) + "\nend\n"
	if n, err := stream.Write([]byte(data)); n != len(data) || err != nil {
		t.Fatalf("converted write = %d, %v", n, err)
	}
	if string(bytes.Join(inner.sent, nil)) != strings.ReplaceAll(data, "\n", "\r\n") {
		t.Fatal("line conversion lost or duplicated bytes")
	}
	for _, p := range inner.sent {
		if len(p) > inner.limit {
			t.Fatalf("converted record too large: %d", len(p))
		}
	}
	inner.incoming = [][]byte{bytes.Repeat([]byte{'r'}, 12000)}
	got, err := io.ReadAll(stream)
	if err != nil || len(got) != 12000 {
		t.Fatalf("adapter hidden by read wrappers: %d, %v", len(got), err)
	}
}
