package netopen

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeARecordDNS is a loopback DNS server that answers A queries with 127.0.0.1.
type fakeARecordDNS struct {
	udp     net.PacketConn
	tcp     net.Listener
	addr    string
	queries atomic.Int32
	wg      sync.WaitGroup
}

func startARecordDNS(t *testing.T) *fakeARecordDNS {
	t.Helper()
	tcp, udp, addr, err := testutil.ListenTCPAndUDP("127.0.0.1", "4")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeARecordDNS{udp: udp, tcp: tcp, addr: addr}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	t.Cleanup(func() {
		_ = s.udp.Close()
		_ = s.tcp.Close()
		s.wg.Wait()
	})
	return s
}

func (s *fakeARecordDNS) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, peer, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		s.queries.Add(1)
		resp, err := aRecordResponse(buf[:n])
		if err == nil {
			_, _ = s.udp.WriteTo(resp, peer)
		}
	}
}

func (s *fakeARecordDNS) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			var size [2]byte
			if _, err := io.ReadFull(c, size[:]); err != nil {
				return
			}
			query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
			if _, err := io.ReadFull(c, query); err != nil {
				return
			}
			s.queries.Add(1)
			resp, err := aRecordResponse(query)
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(resp)))
			_, _ = c.Write(append(size[:], resp...))
		}(conn)
	}
}

func aRecordResponse(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range questions {
		if err := builder.Question(q); err != nil {
			return nil, err
		}
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	for _, q := range questions {
		if q.Type != dnsmessage.TypeA {
			continue
		}
		if err := builder.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  q.Type,
			Class: q.Class,
			TTL:   60,
		}, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

func TestUDPConnectHostnameUsesResNSAddr(t *testing.T) {
	dns := startARecordDNS(t)
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := strconv.Itoa(ln.LocalAddr().(*net.UDPAddr).Port)

	spec, err := parse.ParseSpec("UDP4:udp-dial-res-nsaddr.test:" + port + ",res-nsaddr=" + dns.addr)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openUDP4Connect(t.Context(), spec, xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatalf("UDP connect opener: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if dns.queries.Load() == 0 {
		t.Fatal("UDP connect opener did not query res-nsaddr; Dialer likely used DefaultResolver")
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err := ln.ReadFrom(buf)
		done <- err
	}()
	if _, err := opened.Stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("listener did not receive UDP payload via res-nsaddr: %v", err)
	}
}

func TestRawIPBindHostnameUsesResNSAddr(t *testing.T) {
	dns := startARecordDNS(t)
	spec := parse.Spec{Type: "IP4-SENDTO", Options: []parse.Option{{
		Name:  "res-nsaddr",
		Value: dns.addr,
		Has:   true,
	}}}
	addr, err := resolveRawIPBind(t.Context(), spec, "ip4", "rawip-bind-res-nsaddr.test")
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("bind=%v want 127.0.0.1", addr)
	}
	if dns.queries.Load() == 0 {
		t.Fatal("raw-IP bind= hostname did not query res-nsaddr")
	}

	literal, err := resolveRawIPBind(t.Context(), spec, "ip4", "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !literal.IP.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("literal bind=%v want 127.0.0.2", literal)
	}
}
