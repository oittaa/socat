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
	dns := listenTCPWrapDNS(t)
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
	spec := "UDP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,hosts-allow=" + allow + ",hosts-deny=" + deny + ",res-nsaddr=" + dns
	srv := startForkListenPIPE(t, ctx, g, spec)
	cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+tcpPort(t, srv)+",bind=127.0.0.9")
	echoLive(t, streamOf(t, cli), []byte("once"))
}

// listenTCPWrapDNS answers the first reverse lookup as peer.example and
// later ones as other.example. A second tcpwrap check then misses
// hosts.allow and hits hosts.deny.
func listenTCPWrapDNS(t *testing.T) string {
	t.Helper()
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
			if resp := tcpwrapDNSReply(append([]byte(nil), buf[:n]...), &ptrs); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func tcpwrapDNSReply(query []byte, ptrs *atomic.Int32) []byte {
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
	ip := [4]byte{127, 0, 0, 9}
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
