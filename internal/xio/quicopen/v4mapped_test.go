package quicopen

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/net/dns/dnsmessage"
)

// TestQUIC6V4MappedHostnameConnects binds QUIC-LISTEN on IPv4 and dials
// QUIC,pf=6,ai-v4mapped with an A-only hostname so the client switches udp6
// to udp4 (the same AF_INET workaround as TCP/SCTP/UDP/raw IP).
func TestQUIC6V4MappedHostnameConnects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))
	dns := startQUICARecordDNS(t)

	cs, err := parse.ParseSpec(fmt.Sprintf(
		"QUIC:quic6-v4mapped.test:%d,pf=6,ai-v4mapped,res-nsaddr=%s,verify=0",
		port, dns,
	))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	local := quicNetConnOf(t, o).LocalAddr().(*net.UDPAddr)
	if local.IP.To4() == nil {
		t.Fatalf("QUIC,pf=6,ai-v4mapped local %v want IPv4 socket", local)
	}
	echoRoundtrip(t, o.Stream, []byte("quic6-v4mapped"))
}

func startQUICARecordDNS(t *testing.T) string {
	t.Helper()
	tcp, udp, addr, err := testutil.ListenTCPAndUDP("127.0.0.1", "4")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, err := quicARecordResponse(buf[:n])
			if err == nil {
				_, _ = udp.WriteTo(resp, peer)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			conn, err := tcp.Accept()
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
				resp, err := quicARecordResponse(query)
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(size[:], uint16(len(resp)))
				_, _ = c.Write(append(size[:], resp...))
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
		wg.Wait()
	})
	return addr
}

func quicARecordResponse(query []byte) ([]byte, error) {
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
