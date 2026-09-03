package xio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"golang.org/x/net/dns/dnsmessage"
)

type fakeDNSServer struct {
	udp         net.PacketConn
	tcp         net.Listener
	addr        string
	ptrName     string
	truncateUDP bool
	drop        bool
	udpQueries  atomic.Int32
	tcpQueries  atomic.Int32
	queried     chan struct{}
	wg          sync.WaitGroup

	mu      sync.Mutex
	answer  net.IP
	answers []net.IP
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
	tcp, udp, addr, err := testutil.ListenTCPAndUDP(ip, suffix)
	if err != nil {
		return nil, err
	}
	s := &fakeDNSServer{
		udp:         udp,
		tcp:         tcp,
		addr:        addr,
		answer:      cloneIP(answer),
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
		if s.dropping() {
			continue
		}
		response, err := makeDNSResponse(buf[:n], s.records(), s.ptrName, s.truncateUDP)
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
	if s.dropping() {
		return
	}
	response, err := makeDNSResponse(query, s.records(), s.ptrName, false)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(response)))
	_, _ = conn.Write(append(size[:], response...))
}

func (s *fakeDNSServer) dropping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drop
}

func (s *fakeDNSServer) setAnswers(ips []net.IP) {
	cloned := cloneIPs(ips)
	s.mu.Lock()
	s.answers = cloned
	s.mu.Unlock()
}

func (s *fakeDNSServer) records() []net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.answers) > 0 {
		return cloneIPs(s.answers)
	}
	if s.answer != nil {
		return []net.IP{cloneIP(s.answer)}
	}
	return nil
}

func cloneIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, len(ips))
	for i, ip := range ips {
		out[i] = cloneIP(ip)
	}
	return out
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func makeDNSResponse(query []byte, answers []net.IP, ptrName string, truncated bool) ([]byte, error) {
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
			for _, answer := range answers {
				ip4 := answer.To4()
				if ip4 == nil {
					continue
				}
				var a [4]byte
				copy(a[:], ip4)
				if err := builder.AResource(resourceHeader, dnsmessage.AResource{A: a}); err != nil {
					return nil, err
				}
			}
		case dnsmessage.TypeAAAA:
			for _, answer := range answers {
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
		"::1",
		"[::1]",
		"[::1]:5353",
		"::1::",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseResNSAddr(input); err == nil {
				t.Fatalf("ParseResNSAddr(%q) succeeded", input)
			}
		})
	}
}

func TestParseResNSAddrRejectsIPv6(t *testing.T) {
	for _, input := range []string{"::1", "[::1]", "[::1]:53", "[2001:db8::1]:5353"} {
		_, err := ParseResNSAddr(input)
		if err == nil || !strings.Contains(err.Error(), "IPv6 nameserver is not supported") {
			t.Errorf("ParseResNSAddr(%q) err=%v want IPv6 nameserver is not supported", input, err)
		}
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

func TestResNSAddrHostnameNameserverUsesIPv4(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(server.addr)
	if err != nil {
		t.Fatal(err)
	}

	var decoyHits atomic.Int32
	decoy, decoyErr := net.ListenPacket("udp6", net.JoinHostPort("::1", port))
	if decoyErr != nil {
		t.Logf("no IPv6 loopback decoy: %v", decoyErr)
	} else {
		t.Cleanup(func() { _ = decoy.Close() })
		go func() {
			buf := make([]byte, 512)
			for {
				_, _, readErr := decoy.ReadFrom(buf)
				if readErr != nil {
					return
				}
				decoyHits.Add(1)
			}
		}()
	}

	ips, err := LookupResolver(resNSAddrSpec(net.JoinHostPort("localhost", port))).LookupIP(
		t.Context(), "ip4", "hostname-ns-res-nsaddr.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("LookupIP=%v want 127.0.0.1", ips)
	}
	if server.udpQueries.Load()+server.tcpQueries.Load() == 0 {
		t.Fatal("IPv4-only nameserver received no query for res-nsaddr=localhost")
	}
	if n := decoyHits.Load(); n != 0 {
		t.Fatalf("nameserver hostname contacted IPv6 %d times; want AF_INET only", n)
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
		t.Context(),
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

func TestPeerFilterResolvesRangeOnce(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{
		Name:  "range",
		Value: "range-res-nsaddr.test:255.255.255.255",
		Has:   true,
	})
	filter, err := NewPeerFilter(t.Context(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	queries := server.udpQueries.Load() + server.tcpQueries.Load()
	if queries == 0 {
		t.Fatal("range hostname was not resolved")
	}
	if err := filter.AllowAddr(peer, nil); err != nil {
		t.Fatal(err)
	}
	if err := filter.AllowAddr(peer, nil); err != nil {
		t.Fatal(err)
	}
	if got := server.udpQueries.Load() + server.tcpQueries.Load(); got != queries {
		t.Fatalf("second peer check made another DNS query: got %d, want %d", got, queries)
	}
}

func TestPeerFilterRangeLookupCanceled(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, true)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{
		Name:  "range",
		Value: "cancel-range.test:255.255.255.255",
		Has:   true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := NewPeerFilter(ctx, s, nil)
		result <- err
	}()
	select {
	case <-server.queried:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("range hostname did not query selected nameserver")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("NewPeerFilter error=%v want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer filter ignored context cancellation")
	}
}

func TestReverseHostLookupCanceled(t *testing.T) {
	tests := []struct {
		name  string
		extra []parse.Option
	}{
		{name: "res-nsaddr"},
		{name: "res-usevc", extra: []parse.Option{{Name: "res-usevc"}}},
		{name: "res-usevc=0", extra: []parse.Option{{Name: "res-usevc", Value: "0", Has: true}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, err := startFakeDNS(t, "127.0.0.1", false, true)
			if err != nil {
				t.Fatal(err)
			}
			s := resNSAddrSpec(server.addr)
			s.Options = append(s.Options, tc.extra...)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				_, err := reverseHost(ctx, s, "192.0.2.55")
				result <- err
			}()
			select {
			case <-server.queried:
				cancel()
			case <-time.After(time.Second):
				cancel()
				t.Fatal("reverseHost did not query selected nameserver")
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("reverseHost error=%v want context.Canceled", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("reverseHost ignored context cancellation")
			}
		})
	}
}

func TestLookupResolverWrapsCustomDialOnce(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		extra   []parse.Option
		network string
		packet  bool
	}{
		{name: "res-nsaddr", network: "udp4", packet: true},
		{name: "res-usevc", extra: []parse.Option{{Name: "res-usevc"}}, network: "udp4", packet: false},
		{name: "res-usevc=0", extra: []parse.Option{{Name: "res-usevc", Value: "0", Has: true}}, network: "udp4", packet: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := resNSAddrSpec(server.addr)
			s.Options = append(s.Options, tc.extra...)
			c, err := LookupResolver(s).Dial(t.Context(), tc.network, server.addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			if tc.packet {
				if _, ok := c.(net.PacketConn); !ok {
					t.Fatalf("type %T want net.PacketConn for UDP DNS", c)
				}
				return
			}
			if _, ok := c.(net.PacketConn); ok {
				t.Fatalf("TCP DNS conn %T must not be PacketConn", c)
			}
		})
	}
}

func TestTCPWrapReverseVerificationUsesResNSAddr(t *testing.T) {
	const ptrName = "peer-res-nsaddr.test"
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(192, 0, 2, 55), ptrName, false, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reverseHost(t.Context(), resNSAddrSpec(server.addr), "192.0.2.55")
	if err != nil {
		t.Fatal(err)
	}
	if got != ptrName {
		t.Fatalf("reverseHost=%q want %q", got, ptrName)
	}
	if server.udpQueries.Load() < 2 {
		t.Fatalf("reverse and forward verification made %d DNS queries; want at least 2", server.udpQueries.Load())
	}
}

func TestIPv6OnlyDropsMappedAndIPv4(t *testing.T) {
	got := ipv6Only([]net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("::ffff:192.0.2.1"),
		net.IPv4(192, 0, 2, 2),
		nil,
	})
	if len(got) != 1 || !got[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("ipv6Only=%v want only 2001:db8::1", got)
	}
}

func TestLookupIPV4MappedOmittedDoesNotMap(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	_, err = LookupIP(t.Context(), s, "ip6", "v4mapped-omitted.test")
	if err == nil {
		t.Fatal("omitted ai-v4mapped on A-only name succeeded; C does not default AI_V4MAPPED on")
	}
}

func TestLookupIPV4MappedEnabled(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-v4mapped"})
	ips, err := LookupIP(t.Context(), s, "ip6", "v4mapped-on.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("::ffff:127.0.0.1")) {
		t.Fatalf("LookupIP=%v want ::ffff:127.0.0.1", ips)
	}
	if got := FormatIPForNetwork("tcp6", ips[0]); got != "127.0.0.1" {
		t.Fatalf("FormatIPForNetwork=%q want 127.0.0.1 (Go unmaps IPv4-mapped)", got)
	}
	if got := DialNetwork("udp6", ips[0]); got != "udp4" {
		t.Fatalf("DialNetwork(udp6)=%q want udp4", got)
	}
	if got := DialNetwork("ip6", ips[0]); got != "ip4" {
		t.Fatalf("DialNetwork(ip6)=%q want ip4", got)
	}
}

func TestLookupIPV4MappedDisabled(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-v4mapped", Value: "0", Has: true})
	_, err = LookupIP(t.Context(), s, "ip6", "v4mapped-off.test")
	if err == nil {
		t.Fatal("ai-v4mapped=0 on A-only name succeeded")
	}
}

func TestLookupIPAIAllAppendsMapped(t *testing.T) {
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(127, 0, 0, 1), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setAnswers([]net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")})
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-v4mapped"}, parse.Option{Name: "ai-all"})
	ips, err := LookupIP(t.Context(), s, "ip6", "ai-all.test")
	if err != nil {
		t.Fatal(err)
	}
	var have6, haveMapped bool
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("2001:db8::1")) {
			have6 = true
		}
		if ip.Equal(net.ParseIP("::ffff:192.0.2.1")) {
			haveMapped = true
		}
	}
	if !have6 || !haveMapped {
		t.Fatalf("ai-all ips=%v want native IPv6 and mapped A", ips)
	}
}

func TestLookupIPWithoutAIAllKeepsNativeOnly(t *testing.T) {
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(127, 0, 0, 1), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setAnswers([]net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")})
	s := resNSAddrSpec(server.addr)
	ips, err := LookupIP(t.Context(), s, "ip6", "no-ai-all.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("without ai-all ips=%v want only 2001:db8::1", ips)
	}
}

func TestLookupIPAIAllWithoutV4MappedDoesNotMap(t *testing.T) {
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(127, 0, 0, 1), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setAnswers([]net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")})
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-all"})
	ips, err := LookupIP(t.Context(), s, "ip6", "all-without-v4mapped.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("ai-all without ai-v4mapped ips=%v want only native IPv6", ips)
	}
}

func TestResUseVCQueriesTCP(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "res-usevc"})
	ips, err := LookupIP(t.Context(), s, "ip4", "usevc.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("LookupIP=%v", ips)
	}
	if server.tcpQueries.Load() == 0 {
		t.Fatal("res-usevc made no TCP DNS queries")
	}
	if server.udpQueries.Load() != 0 {
		t.Fatalf("res-usevc made %d UDP queries; want 0", server.udpQueries.Load())
	}
}

func TestResUseVCZeroKeepsUDP(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "res-usevc", Value: "0", Has: true})
	if _, err := LookupIP(t.Context(), s, "ip4", "usevc-off.test"); err != nil {
		t.Fatal(err)
	}
	if server.udpQueries.Load() == 0 {
		t.Fatal("res-usevc=0 made no UDP DNS queries")
	}
	if server.tcpQueries.Load() != 0 {
		t.Fatalf("res-usevc=0 made %d TCP queries; want 0 for a non-truncated UDP answer", server.tcpQueries.Load())
	}
}

func TestResUseVCZeroTruncatedUDPRetriesTCP(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", true, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "res-usevc", Value: "0", Has: true})
	// Trailing dot keeps the name absolute so resolv.conf search does not
	// add extra queries that would loosen the UDP/TCP counts.
	ips, err := LookupIP(t.Context(), s, "ip4", "usevc-off-truncate.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("LookupIP=%v", ips)
	}
	if udp, tcp := server.udpQueries.Load(), server.tcpQueries.Load(); udp != 1 || tcp != 1 {
		t.Fatalf("res-usevc=0 truncated lookup made %d UDP and %d TCP queries; want 1 and 1 (not UDP→UDP→TCP)", udp, tcp)
	}
}

func TestResUseVCZeroTCPDialRetriesTruncatedUDP(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", true, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "res-usevc", Value: "0", Has: true})
	r := LookupResolver(s)
	if r == net.DefaultResolver {
		t.Fatal("res-usevc=0 returned process-global DefaultResolver; cannot clear resolv.conf use-vc")
	}
	if r.Dial == nil {
		t.Fatal("res-usevc=0 resolver has no Dial rewrite")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	c, err := r.Dial(ctx, "tcp4", server.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, ok := c.(net.PacketConn); ok {
		t.Fatalf("res-usevc=0 Dial(tcp4) type %T is PacketConn; Go would skip TCP fallback", c)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	name, err := dnsmessage.NewName("usevc-tcp-truncate.test.")
	if err != nil {
		t.Fatal(err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	if _, err := c.Write(append(hdr[:], query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(hdr[:])))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if dnsMessageTruncated(resp) {
		t.Fatal("TCP-framed response still truncated")
	}
	if udp, tcp := server.udpQueries.Load(), server.tcpQueries.Load(); udp != 1 || tcp != 1 {
		t.Fatalf("res-usevc=0 TCP Dial made %d UDP and %d TCP queries; want 1 and 1", udp, tcp)
	}
}

func TestAIAddrConfigDefaultOnUnspecifiedHint(t *testing.T) {
	if !addrconfigEnabled(parse.Spec{}, "ip") {
		t.Fatal("omitted ai-addrconfig with hint ip: want default on")
	}
	if addrconfigEnabled(parse.Spec{}, "ip4") || addrconfigEnabled(parse.Spec{}, "ip6") {
		t.Fatal("omitted ai-addrconfig with family hint: want default off")
	}
	off := parse.Spec{Options: []parse.Option{{Name: "ai-addrconfig", Value: "0", Has: true}}}
	if addrconfigEnabled(off, "ip") {
		t.Fatal("ai-addrconfig=0 with hint ip: want off")
	}
	on := parse.Spec{Options: []parse.Option{{Name: "ai-addrconfig"}}}
	if !addrconfigEnabled(on, "ip6") {
		t.Fatal("ai-addrconfig with hint ip6: want on")
	}
}

func TestLookupIPAIAddrConfigOmittedFiltersUnspecifiedHint(t *testing.T) {
	restore := localIPFamilies
	t.Cleanup(func() { localIPFamilies = restore })
	localIPFamilies = func() (bool, bool) { return true, false }

	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(127, 0, 0, 1), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setAnswers([]net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")})
	s := resNSAddrSpec(server.addr)
	ips, err := LookupIP(t.Context(), s, "ip", "addrconfig-default.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].To4() == nil {
		t.Fatalf("default AI_ADDRCONFIG hint=ip ips=%v want only IPv4", ips)
	}

	forced, err := LookupIP(t.Context(), s, "ip6", "addrconfig-family.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(forced) != 1 || forced[0].To4() != nil {
		t.Fatalf("omitted addrconfig hint=ip6 ips=%v want native IPv6 (no default filter)", forced)
	}

	s.Options = append(s.Options, parse.Option{Name: "ai-addrconfig", Value: "0", Has: true})
	both, err := LookupIP(t.Context(), s, "ip", "addrconfig-zero.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(both) < 2 {
		t.Fatalf("ai-addrconfig=0 ips=%v want both families", both)
	}
}

func TestLocalIPFamiliesFromAddrsSkipLoopback(t *testing.T) {
	loopbackOnly := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
	}
	v4, v6 := localIPFamiliesFromAddrs(loopbackOnly)
	if v4 || v6 {
		t.Fatalf("loopback-only families v4=%v v6=%v; Linux AI_ADDRCONFIG ignores loopback", v4, v6)
	}

	v4Only := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)},
	}
	v4, v6 = localIPFamiliesFromAddrs(v4Only)
	if !v4 || v6 {
		t.Fatalf("non-loopback IPv4 only: v4=%v v6=%v want v4 only", v4, v6)
	}

	v6Only := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
	}
	v4, v6 = localIPFamiliesFromAddrs(v6Only)
	if v4 || !v6 {
		t.Fatalf("non-loopback IPv6 only: v4=%v v6=%v want v6 only", v4, v6)
	}
}

func TestLookupIPAIAddrConfigLoopbackOnlyFamily(t *testing.T) {
	restore := localIPFamilies
	t.Cleanup(func() { localIPFamilies = restore })
	localIPFamilies = func() (bool, bool) {
		return localIPFamiliesFromAddrs([]net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
		})
	}

	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(127, 0, 0, 1), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setAnswers([]net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")})
	s := resNSAddrSpec(server.addr)
	ips, err := LookupIP(t.Context(), s, "ip", "addrconfig-loopback-v4.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].To4() != nil {
		t.Fatalf("AI_ADDRCONFIG with loopback-only IPv4 ips=%v want only IPv6", ips)
	}
}

func TestLookupIPAIPassivePrefersIPv6OnUnspecifiedHint(t *testing.T) {
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(127, 0, 0, 1), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setAnswers([]net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")})
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-addrconfig", Value: "0", Has: true}, parse.Option{Name: "ai-passive"})
	ips, err := LookupIP(t.Context(), s, "ip", "passive-pref.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) < 2 || ips[0].To4() != nil {
		t.Fatalf("ai-passive hint=ip ips=%v want IPv6 first", ips)
	}
}

func TestResUseVCAndV4MappedDoNotMutateDefaultResolver(t *testing.T) {
	before := net.DefaultResolver
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := parse.Spec{Options: []parse.Option{
		{Name: "res-usevc"},
		{Name: "ai-v4mapped"},
		{Name: "ai-all"},
	}}
	resolver := LookupResolver(s)
	if resolver == before {
		t.Fatal("res-usevc returned process-global DefaultResolver")
	}
	s.Options = append(s.Options, parse.Option{Name: "res-nsaddr", Value: server.addr, Has: true})
	if _, err := LookupIP(t.Context(), s, "ip4", "isolated-usevc.test"); err != nil {
		t.Fatal(err)
	}
	if net.DefaultResolver != before {
		t.Fatal("resolver options replaced net.DefaultResolver")
	}
}

func TestDialTCPAllV4MappedConnects(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Type = "TCP6"
	s.Options = append(s.Options, parse.Option{Name: "ai-v4mapped"})
	c, err := DialTCPAll(t.Context(), "tcp6", "v4mapped-dial.test", port, s, nil, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	<-done
}

func TestPacketNetworkForHostV4Mapped(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-v4mapped"})
	got, err := PacketNetworkForHost(t.Context(), s, "udp6", "v4mapped-packet.test")
	if err != nil {
		t.Fatal(err)
	}
	if got != "udp4" {
		t.Fatalf("PacketNetworkForHost=%q want udp4", got)
	}
	got, err = PacketNetworkForHost(t.Context(), s, "udp6", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "udp6" {
		t.Fatalf("IPv4 literal PacketNetworkForHost=%q want udp6 (no silent family switch)", got)
	}
}

func TestLookupDialIPAIPassivePrefersIPv6(t *testing.T) {
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(127, 0, 0, 1), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setAnswers([]net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")})
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-addrconfig", Value: "0", Has: true}, parse.Option{Name: "ai-passive"})
	netw, ip, err := LookupDialIP(t.Context(), s, "udp", "passive-udp.test")
	if err != nil {
		t.Fatal(err)
	}
	if netw != "udp6" || ip.To4() != nil {
		t.Fatalf("LookupDialIP udp+ai-passive = %s %v want udp6 IPv6", netw, ip)
	}
}

func TestMatchLocalPacketAddrUnspecified(t *testing.T) {
	got, err := MatchLocalPacketAddr("udp4", &net.UDPAddr{IP: net.IPv6zero, Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	ua := got.(*net.UDPAddr)
	if ua.Port != 9 || ua.IP.To4() == nil || !ua.IP.IsUnspecified() {
		t.Fatalf("got %+v want IPv4 unspecified port 9", ua)
	}
	_, err = MatchLocalPacketAddr("udp4", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9})
	if err == nil {
		t.Fatal("specified IPv6 bind on udp4: want mismatch")
	}
}

func ExampleParseResNSAddr() {
	addr, _ := ParseResNSAddr("127.0.0.1:5353")
	fmt.Println(addr)
	// Output: 127.0.0.1:5353
}
