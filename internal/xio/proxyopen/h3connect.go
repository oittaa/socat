package proxyopen

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

// testHookH3PacketConn, when set, sees the HTTP/3 UDP PacketConn after
// ListenControl applied PH_PASTSOCKET options and before QUIC dials on it.
var testHookH3PacketConn func(net.PacketConn)

func tcpToUDPNetwork(tcpNet string) string {
	switch strings.ToLower(tcpNet) {
	case "tcp4":
		return "udp4"
	case "tcp6":
		return "udp6"
	default:
		return "udp"
	}
}

// listenH3Packet binds the HTTP/3 UDP socket with ListenControl so send-side
// IP options (ip-ttl, ip-tos, ip-options, ipv6-unicast-hops, ipv6-tclass)
// apply once at PH_PASTSOCKET after socket() and before bind, matching
// quicopen.listenPacket / listenQUICClientPacket.
func listenH3Packet(ctx context.Context, s parse.Spec, g *xio.Global, proxyHost string) (net.PacketConn, string, error) {
	network := tcpToUDPNetwork(xio.ConnectNetworkForType(g, s, proxyHost, "tcp"))
	bindHost, err := xio.ListenBindHost(network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, "", err
	}
	sourceport := s.OptionValue("sourceport", "")
	if sourceport == "" {
		sourceport = "0"
	}
	laddr := net.JoinHostPort(xio.StripBrackets(bindHost), sourceport)
	lc := net.ListenConfig{Control: xio.ListenControl(s)}
	pc, err := lc.ListenPacket(ctx, network, laddr)
	if err != nil {
		return nil, "", err
	}
	if err := xio.ApplyLateSocketOptionsToPacketConn(pc, s); err != nil {
		_ = pc.Close()
		return nil, "", err
	}
	return pc, network, nil
}

func dialH3CONNECT(ctx context.Context, s parse.Spec, g *xio.Global, t proxyTarget) (net.Conn, error) {
	tlsCfg, err := tlsopen.TLSClientConfig(s, t.proxyHost)
	if err != nil {
		return nil, err
	}
	tlsCfg = tlsCfg.Clone()
	if tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	tlsCfg.NextProtos = []string{proxyALPN(s, http3.NextProtoH3)}

	pc, network, err := listenH3Packet(ctx, s, g, t.proxyHost)
	if err != nil {
		return nil, err
	}
	if h := testHookH3PacketConn; h != nil {
		h(pc)
	}
	qtr := &quic.Transport{Conn: pc}
	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
		Dial: func(dctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			raddr, e := net.ResolveUDPAddr(network, addr)
			if e != nil {
				return nil, e
			}
			return qtr.Dial(dctx, raddr, tlsCfg, cfg)
		},
	}
	closeH3 := func() error {
		_ = tr.Close()
		_ = qtr.Close()
		return pc.Close()
	}

	u := "https://" + net.JoinHostPort(xio.StripBrackets(t.proxyHost), t.proxyPort) + "/"
	authority := net.JoinHostPort(t.connectHost, t.targetPort)

	var conn net.Conn
	err = xio.WithRetry(ctx, s, g, "PROXY-CONNECT", func() error {
		pr, pw := io.Pipe()
		req, e := http.NewRequestWithContext(ctx, http.MethodConnect, u, pr)
		if e != nil {
			_ = pw.Close()
			return e
		}
		req.Host = authority
		req.ContentLength = -1
		if auth, e := proxyAuthString(s); e != nil {
			_ = pw.Close()
			return e
		} else if auth != "" {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		}
		resp, e := tr.RoundTrip(req)
		if e != nil {
			_ = pw.Close()
			return e
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			_ = pw.Close()
			_ = resp.Body.Close()
			return fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
		}
		conn = &pipeConn{
			r:      resp.Body,
			w:      pw,
			local:  staticAddr("h3", u),
			remote: staticAddr("h3", authority),
			extra:  []io.Closer{closerFunc(closeH3)},
		}
		return nil
	})
	if err != nil {
		_ = closeH3()
		return nil, err
	}
	return conn, nil
}
