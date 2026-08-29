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
	"golang.org/x/net/dns/dnsmessage"
)

type fakeDNSServer struct {
	udp         net.PacketConn
	tcp         net.Listener
	addr        string
	answer      net.IP
	answers     []net.IP
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

// listenTCPAndUDP binds TCP and UDP on the same port. Windows Hyper-V
// excluded port ranges can make Listen(":0") or the follow-up bind on the
// sibling protocol fail with WSAEACCES ("access permissions"); retry until
// both succeed.
func listenTCPAndUDP(ip, suffix string) (tcp net.Listener, udp net.PacketConn, addr string, err error) {
	const attempts = 64
	hostport0 := net.JoinHostPort(ip, "0")
	var last error
	for i := 0; i < attempts; i++ {
		tcp, last = net.Listen("tcp"+suffix, hostport0)
		if last != nil {
			continue
		}
		_, port, splitErr := net.SplitHostPort(tcp.Addr().String())
		if splitErr != nil {
			_ = tcp.Close()
			return nil, nil, "", splitErr
		}
		addr = net.JoinHostPort(ip, port)
		udp, last = net.ListenPacket("udp"+suffix, addr)
		if last == nil {
			return tcp, udp, addr, nil
		}
		_ = tcp.Close()
	}
	if last == nil {
		last = fmt.Errorf("listen tcp+udp %s: no port after %d attempts", net.JoinHostPort(ip, "0"), attempts)
	}
	return nil, nil, "", last
}

func startFakeDNSWithAnswer(t *testing.T, ip string, answer net.IP, ptrName string, truncateUDP, drop bool) (*fakeDNSServer, error) {
	t.Helper()
	suffix := "4"
	if net.ParseIP(ip).To4() == nil {
		suffix = "6"
	}
	tcp, udp, addr, err := listenTCPAndUDP(ip, suffix)
	if err != nil {
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
	if s.drop {
		return
	}
	response, err := makeDNSResponse(query, s.records(), s.ptrName, false)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(response)))
	_, _ = conn.Write(append(size[:], response...))
}

func (s *fakeDNSServer) records() []net.IP {
	if len(s.answers) > 0 {
		return s.answers
	}
	if s.answer != nil {
		return []net.IP{s.answer}
	}
	return nil
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

func TestLookupIPV4MappedDefault(t *testing.T) {
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s := resNSAddrSpec(server.addr)
	ips, err := LookupIP(t.Context(), s, "ip6", "v4mapped-default.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("::ffff:127.0.0.1")) {
		t.Fatalf("LookupIP=%v want ::ffff:127.0.0.1", ips)
	}
	if got := FormatIPForNetwork("tcp6", ips[0]); got != "::ffff:127.0.0.1" {
		t.Fatalf("FormatIPForNetwork=%q", got)
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
	server.answers = []net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")}
	s := resNSAddrSpec(server.addr)
	s.Options = append(s.Options, parse.Option{Name: "ai-all"})
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
	server.answers = []net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")}
	s := resNSAddrSpec(server.addr)
	ips, err := LookupIP(t.Context(), s, "ip6", "no-ai-all.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("without ai-all ips=%v want only 2001:db8::1", ips)
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
	ln, err := net.Listen("tcp6", "[::ffff:127.0.0.1]:0")
	if err != nil {
		t.Skip(err)
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
	c, err := DialTCPAll(t.Context(), "tcp6", "v4mapped-dial.test", port, s, nil, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	<-done
}

func ExampleParseResNSAddr() {
	addr, _ := ParseResNSAddr("127.0.0.1:5353")
	fmt.Println(addr)
	// Output: 127.0.0.1:5353
}
