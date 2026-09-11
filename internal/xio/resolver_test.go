package xio

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
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

func resolverConfig(t *testing.T, s parse.Spec) addrconfig.Address {
	t.Helper()
	config, err := addrconfig.Decode(s, addrconfig.Facts{Type: s.Type})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func resNSAddrSpec(addr string) parse.Spec {
	return parse.Spec{Type: "TCP4", Options: []parse.Option{{
		Name:  "res-nsaddr",
		Value: addr,
		Has:   true,
	}}}
}

func TestParseResNSAddrRejectsIPv6(t *testing.T) {
	for _, input := range []string{"::1", "[::1]", "[::1]:53", "[2001:db8::1]:5353"} {
		_, err := ParseResNSAddr(input)
		if err == nil || !strings.Contains(err.Error(), "IPv6 nameserver is not supported") {
			t.Errorf("ParseResNSAddr(%q) err=%v want IPv6 nameserver is not supported", input, err)
		}
	}
}

func TestResNSAddrResolverDoesNotMutateDefaultResolver(t *testing.T) {
	before := net.DefaultResolver
	server, err := startFakeDNS(t, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	resolver := LookupResolver(resolverConfig(t, resNSAddrSpec(server.addr)))
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
	resolver := LookupResolver(resolverConfig(t, s))
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

func TestTCPWrapReverseVerificationUsesResNSAddr(t *testing.T) {
	const ptrName = "peer-res-nsaddr.test"
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.IPv4(192, 0, 2, 55), ptrName, false, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reverseHost(t.Context(), LookupResolver(resolverConfig(t, resNSAddrSpec(server.addr))), "192.0.2.55")
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

func TestAIAddrConfigDefaultOnUnspecifiedHint(t *testing.T) {
	empty := addrconfig.Address{}
	if !addrconfigEnabled(empty, "ip") {
		t.Fatal("omitted ai-addrconfig with hint ip: want default on")
	}
	if addrconfigEnabled(empty, "ip4") || addrconfigEnabled(empty, "ip6") {
		t.Fatal("omitted ai-addrconfig with family hint: want default off")
	}
	off := resolverConfig(t, parse.Spec{Options: []parse.Option{{Name: "ai-addrconfig", Value: "0", Has: true}}})
	if addrconfigEnabled(off, "ip") {
		t.Fatal("ai-addrconfig=0 with hint ip: want off")
	}
	on := resolverConfig(t, parse.Spec{Options: []parse.Option{{Name: "ai-addrconfig"}}})
	if !addrconfigEnabled(on, "ip6") {
		t.Fatal("ai-addrconfig with hint ip6: want on")
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
