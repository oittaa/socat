package xio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/net/dns/dnsmessage"
)

type fakeDNSServer struct {
	udp         net.PacketConn
	tcp         net.Listener
	addr        string
	answer      net.IP
	ptrName     string
	truncateUDP bool
	drop        bool
	udpQueries  atomic.Int32
	tcpQueries  atomic.Int32
	queried     chan struct{}
	wg          sync.WaitGroup
}

func startFakeDNS(t *testing.T, ip string, truncateUDP, drop bool) (*fakeDNSServer, error) {
	return startFakeDNSWithAnswer(t, ip, net.IPv4(127, 0, 0, 1), "", truncateUDP, drop)
}

func startFakeDNSWithAnswer(t *testing.T, ip string, answer net.IP, ptrName string, truncateUDP, drop bool) (*fakeDNSServer, error) {
	t.Helper()
	suffix := "4"
	if net.ParseIP(ip).To4() == nil {
		suffix = "6"
	}
	udp, err := net.ListenPacket("udp"+suffix, net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	_, port, err := net.SplitHostPort(udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	addr := net.JoinHostPort(ip, port)
	tcp, err := net.Listen("tcp"+suffix, addr)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	s := &fakeDNSServer{
		udp:         udp,
		tcp:         tcp,
		addr:        addr,
		answer:      answer,
		ptrName:     ptrName,
		truncateUDP: truncateUDP,
		drop:        drop,
		queried:     make(chan struct{}, 1),
	}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	t.Cleanup(func() {
		_ = s.udp.Close()
		_ = s.tcp.Close()
		s.wg.Wait()
	})
	return s, nil
}

func (s *fakeDNSServer) noteQuery(counter *atomic.Int32) {
	counter.Add(1)
	select {
	case s.queried <- struct{}{}:
	default:
	}
}

func (s *fakeDNSServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, peer, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		s.noteQuery(&s.udpQueries)
		if s.drop {
			continue
		}
		response, err := makeDNSResponse(buf[:n], s.answer, s.ptrName, s.truncateUDP)
		if err == nil {
			_, _ = s.udp.WriteTo(response, peer)
		}
	}
}

func (s *fakeDNSServer) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go s.serveTCPConn(conn)
	}
}

func (s *fakeDNSServer) serveTCPConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return
	}
	query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}
	s.noteQuery(&s.tcpQueries)
	if s.drop {
		return
	}
	response, err := makeDNSResponse(query, s.answer, s.ptrName, false)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(response)))
	_, _ = conn.Write(append(size[:], response...))
}

func makeDNSResponse(query []byte, answer net.IP, ptrName string, truncated bool) ([]byte, error) {
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
		Truncated:          truncated,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	for _, question := range questions {
		if err := builder.Question(question); err != nil {
			return nil, err
		}
	}
	if truncated {
		return builder.Finish()
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	for _, question := range questions {
		resourceHeader := dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  question.Type,
			Class: question.Class,
			TTL:   60,
		}
		switch question.Type {
		case dnsmessage.TypeA:
			ip4 := answer.To4()
			if ip4 == nil {
				continue
			}
			var a [4]byte
			copy(a[:], ip4)
			if err := builder.AResource(resourceHeader, dnsmessage.AResource{A: a}); err != nil {
				return nil, err
			}
		case dnsmessage.TypeAAAA:
			if answer.To4() != nil {
				continue
			}
			ip16 := answer.To16()
			if ip16 == nil {
				continue
			}
			var aaaa [16]byte
			copy(aaaa[:], ip16)
			if err := builder.AAAAResource(resourceHeader, dnsmessage.AAAAResource{AAAA: aaaa}); err != nil {
				return nil, err
			}
		case dnsmessage.TypePTR:
			if ptrName == "" {
				continue
			}
			ptr, err := dnsmessage.NewName(ptrName + ".")
			if err != nil {
				return nil, err
			}
			if err := builder.PTRResource(resourceHeader, dnsmessage.PTRResource{PTR: ptr}); err != nil {
				return nil, err
			}
		}
	}
	return builder.Finish()
}

func resNSAddrSpec(addr string) parse.Spec {
	return parse.Spec{Type: "TCP4", Options: []parse.Option{{
		Name:  "res-nsaddr",
		Value: addr,
		Has:   true,
	}}}
}

func TestParseResNSAddrForms(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"127.0.0.1", "127.0.0.1:53"},
		{"127.0.0.1:0", "127.0.0.1:53"},
		{"127.0.0.1:5353", "127.0.0.1:5353"},
		{"localhost", "localhost:53"},
		{"localhost:domain", "localhost:53"},
		{"::1", "[::1]:53"},
		{"[::1]", "[::1]:53"},
		{"[::1]:0", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseResNSAddr(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ParseResNSAddr(%q)=%q want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseResNSAddrErrors(t *testing.T) {
	for _, input := range []string{
		"",
		"bad host",
		"-bad.example",
		"127.0.0.1:",
		"127.0.0.1:65536",
		"[::1",
		"[::1]:",
		"[::1]extra",
		"::1::",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseResNSAddr(input); err == nil {
				t.Fatalf("ParseResNSAddr(%q) succeeded", input)
			}
		})
	}
}

func TestResNSAddrConnectUsesOnlySelectedServerAndTCPFallback(t *testing.T) {
	selected, err := startFakeDNS(t, "127.0.0.1", true, false)
	if err != nil {
		t.Fatal(err)
	}
	other, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		accepted <- acceptErr
	}()

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	conn, err := DialTCPAll(t.Context(), "tcp4", "selected-res-nsaddr.test", port, resNSAddrSpec(selected.addr), nil, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	if selected.udpQueries.Load() == 0 {
		t.Fatal("selected nameserver received no UDP query")
	}
	if selected.tcpQueries.Load() == 0 {
		t.Fatal("truncated UDP response did not retry over TCP")
	}
	if got := other.udpQueries.Load() + other.tcpQueries.Load(); got != 0 {
		t.Fatalf("unselected nameserver received %d queries", got)
	}
}

func TestResNSAddrLiteralConnectDoesNotQueryDNS(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	conn, err := DialTCPAll(t.Context(), "tcp4", "127.0.0.1", port, resNSAddrSpec(server.addr), nil, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := server.udpQueries.Load() + server.tcpQueries.Load(); got != 0 {
		t.Fatalf("literal IP caused %d DNS queries", got)
	}
}

func TestResNSAddrIPv6Nameserver(t *testing.T) {
	server, err := startFakeDNS(t, "::1", false, false)
	if err != nil {
		t.Skipf("IPv6 loopback cannot host UDP and TCP DNS listeners: %v", err)
	}
	ips, err := LookupResolver(resNSAddrSpec(server.addr)).LookupIP(t.Context(), "ip4", "ipv6-res-nsaddr.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("LookupIP=%v want 127.0.0.1", ips)
	}
	if server.udpQueries.Load() == 0 {
		t.Fatal("IPv6 nameserver received no query")
	}
}

func TestResNSAddrLookupContextCancellation(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, lookupErr := LookupResolver(resNSAddrSpec(server.addr)).LookupIP(ctx, "ip4", "cancel-res-nsaddr.test")
		result <- lookupErr
	}()
	select {
	case <-server.queried:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("lookup did not query selected nameserver")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lookup error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lookup ignored context cancellation")
	}
}

func TestResNSAddrResolverDoesNotMutateDefaultResolver(t *testing.T) {
	before := net.DefaultResolver
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	resolver := LookupResolver(resNSAddrSpec(server.addr))
	if resolver == before {
		t.Fatal("res-nsaddr returned process-global DefaultResolver")
	}
	if _, err := resolver.LookupIP(t.Context(), "ip4", "isolated-res-nsaddr.test"); err != nil {
		t.Fatal(err)
	}
	if net.DefaultResolver != before {
		t.Fatal("res-nsaddr replaced net.DefaultResolver")
	}
}

func TestLookupResolverCombinesNetNSAndResNSAddr(t *testing.T) {
	s := resNSAddrSpec("127.0.0.1:5353")
	s.Options = append(s.Options, parse.Option{Name: "netns", Value: "test", Has: true})
	resolver := LookupResolver(s)
	if resolver == nil || !resolver.PreferGo || resolver.Dial == nil {
		t.Fatalf("combined resolver=%+v; want PreferGo custom Dial", resolver)
	}
}

func TestResolveUDPAddrUsesResNSAddr(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := ResolveUDPAddr(t.Context(), resNSAddrSpec(server.addr), "udp4", "udp-res-nsaddr.test:9")
	if err != nil {
		t.Fatal(err)
	}
	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) || addr.Port != 9 {
		t.Fatalf("ResolveUDPAddr=%v want 127.0.0.1:9", addr)
	}
	if server.udpQueries.Load() == 0 {
		t.Fatal("UDP target hostname did not use selected nameserver")
	}
}

func TestPeerRangeHostnameUsesResNSAddr(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := ipInRangeWithResolver(
		net.IPv4(127, 0, 0, 1),
		"range-res-nsaddr.test:255.255.255.255",
		LookupResolver(resNSAddrSpec(server.addr)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("peer range hostname resolved by selected server did not match")
	}
	if server.udpQueries.Load() == 0 {
		t.Fatal("peer range hostname did not query selected nameserver")
	}
}

func TestTCPWrapReverseVerificationUsesResNSAddr(t *testing.T) {
	const ptrName = "peer-res-nsaddr.test"
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(192, 0, 2, 55), ptrName, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := reverseHost(resNSAddrSpec(server.addr), "192.0.2.55"); got != ptrName {
		t.Fatalf("reverseHost=%q want %q", got, ptrName)
	}
	if server.udpQueries.Load() < 2 {
		t.Fatalf("reverse and forward verification made %d DNS queries; want at least 2", server.udpQueries.Load())
	}
}

func ExampleParseResNSAddr() {
	addr, _ := ParseResNSAddr("[2001:db8::53]:5353")
	fmt.Println(addr)
	// Output: [2001:db8::53]:5353
}
