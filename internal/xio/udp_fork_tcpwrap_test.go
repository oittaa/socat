package xio_test

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestUDPForkTCPWrapAllowsPeerAfterOneLookup(t *testing.T) {
	ip := assignedIPv4(t)
	dns := listenTCPWrapDNS(t, ip)
	dir := t.TempDir()
	allow := filepath.Join(dir, "hosts.allow")
	deny := filepath.Join(dir, "hosts.deny")
	if err := os.WriteFile(allow, []byte("socat: peer.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, g := testCtx(t), testGlobal()
	bind := ip.String()
	spec := "UDP4-LISTEN:0,reuseaddr,fork,bind=" + bind + ",hosts-allow=" + allow + ",hosts-deny=" + deny + ",res-nsaddr=" + dns
	srv := startForkListenPIPE(t, ctx, g, spec)
	cli := openClient(t, ctx, g, "UDP4:"+bind+":"+tcpPort(t, srv)+",bind="+bind)
	echoLive(t, streamOf(t, cli), []byte("once"))
}

// assignedIPv4 is an address the kernel already selected for this host.
// 127.0.0.1 is in the hosts file, so reverse lookup would never reach the
// test nameserver. Other 127/8 addresses are not assigned on macOS.
func assignedIPv4(t *testing.T) net.IP {
	t.Helper()
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	ip := net.IP(nil)
	if ok {
		ip = addr.IP.To4()
	}
	if ip == nil || ip.IsLoopback() {
		t.Fatal("no assigned non-loopback IPv4 address")
	}
	return ip
}

// listenTCPWrapDNS answers the first reverse lookup as peer.example and
// later ones as other.example. A second tcpwrap check then misses
// hosts.allow and hits hosts.deny.
func listenTCPWrapDNS(t *testing.T, peer net.IP) string {
	t.Helper()
	var peer4 [4]byte
	copy(peer4[:], peer.To4())
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var ptrs atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := tcpwrapDNSReply(append([]byte(nil), buf[:n]...), peer4, &ptrs); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func tcpwrapDNSReply(query []byte, peer [4]byte, ptrs *atomic.Int32) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) == 0 {
		return nil
	}
	q := questions[0]
	host := "peer.example."
	ip := peer
	if q.Type == dnsmessage.TypePTR && ptrs.Add(1) > 1 {
		host = "other.example."
	}
	if q.Type != dnsmessage.TypePTR && q.Name.String() == "other.example." {
		host = "other.example."
		ip = [4]byte{10, 0, 0, 1}
	}
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil
	}
	if err := builder.Question(q); err != nil {
		return nil
	}
	if err := builder.StartAnswers(); err != nil {
		return nil
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}
	switch q.Type {
	case dnsmessage.TypePTR:
		err = builder.PTRResource(rh, dnsmessage.PTRResource{PTR: name})
	case dnsmessage.TypeCNAME:
		err = builder.CNAMEResource(rh, dnsmessage.CNAMEResource{CNAME: name})
	case dnsmessage.TypeA:
		err = builder.AResource(rh, dnsmessage.AResource{A: ip})
	default:
		err = nil
	}
	if err != nil {
		return nil
	}
	out, err := builder.Finish()
	if err != nil {
		return nil
	}
	return out
}
