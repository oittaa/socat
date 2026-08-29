package proxyopen

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
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

// listenH3Packet binds the HTTP/3 UDP socket with ListenControl so PH_PASTSOCKET
// options, including send-side IP/ancillary options and multicast joins,
// apply once after socket() and before bind. http3.Transport would otherwise
// create its own UDP socket and silently ignore those requested options.
func listenH3Packet(ctx context.Context, s parse.Spec, g *xio.Global, proxyHost string) (net.PacketConn, string, error) {
	network := tcpToUDPNetwork(xio.ConnectNetworkForType(g, s, proxyHost, "tcp"))
	netw, err := xio.PacketNetworkForHost(ctx, s, network, proxyHost)
	if err != nil {
		return nil, "", err
	}
	network = netw
	bindHost, err := xio.ListenBindHost(s, network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, "", err
	}
	sourceport := s.OptionValue("sourceport", "")
	lc := net.ListenConfig{Control: xio.ListenControl(s)}
	listen := func(port string) (net.PacketConn, error) {
		laddr := net.JoinHostPort(xio.StripBrackets(bindHost), port)
		resolved, resolveErr := xio.ResolveUDPAddr(ctx, s, network, laddr)
		if resolveErr != nil {
			return nil, resolveErr
		}
		return lc.ListenPacket(ctx, network, resolved.String())
	}
	var pc net.PacketConn
	if s.BoolOption("lowport") && (sourceport == "" || sourceport == "0") {
		_, err = xio.FirstAvailableLowport(func(port int) error {
			if g != nil && g.Log != nil {
				g.Log.Debugf("bind(%s:%d)", bindHost, port)
			}
			pc, err = listen(strconv.Itoa(port))
			return err
		})
		if err != nil {
			return nil, "", fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", xio.LowportMin, xio.LowportMax, err)
		}
	} else {
		if sourceport == "" {
			sourceport = "0"
		}
		pc, err = listen(sourceport)
	}
	if err != nil {
		return nil, "", err
	}
	// The explicit PacketConn must carry the same post-bind phases as direct
	// QUIC. Otherwise options accepted on PROXY,http-version=3 would become
	// silent no-ops merely because http3.Transport no longer owns the socket.
	if err := xio.ApplyLateSocketOptionsToPacketConn(pc, s); err != nil {
		_ = pc.Close()
		return nil, "", err
	}
	// Descriptor lifecycle on the HTTP/3 UDP socket before quic-go wrapping
	// (classic has no HTTP/3; never accept append/perm on the stream wrapper).
	if err := xio.ApplyFDLifecycleToPacketConn(pc, s); err != nil {
		_ = pc.Close()
		return nil, "", err
	}
	if err := xio.ApplyGenericSetsockoptToPacketConn(pc, s, xio.SockoptPhaseConnected); err != nil {
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

	u := "https://" + net.JoinHostPort(xio.StripBrackets(t.proxyHost), t.proxyPort) + "/"
	authority := net.JoinHostPort(t.connectHost, t.targetPort)
	attemptTimeout := xio.CombinedConnectHandshakeTimeout(s)
	idle := xio.QUICHandshakeIdleTimeout(s)

	var conn net.Conn
	err = xio.WithRetry(ctx, s, g, "PROXY-CONNECT", func() error {
		cctx, stopTimer, cancelHandshake := proxyHandshakeContext(ctx, attemptTimeout)
		pc, network, e := listenH3Packet(cctx, s, g, t.proxyHost)
		if e != nil {
			stopTimer()
			cancelHandshake()
			return e
		}
		if h := testHookH3PacketConn; h != nil {
			h(pc)
		}
		qtr := &quic.Transport{Conn: pc}
		tr := &http3.Transport{
			TLSClientConfig: tlsCfg.Clone(),
			QUICConfig:      &quic.Config{HandshakeIdleTimeout: idle},
			Dial: func(dctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				raddr, resolveErr := xio.ResolveUDPAddr(dctx, s, network, addr)
				if resolveErr != nil {
					return nil, resolveErr
				}
				return qtr.Dial(dctx, raddr, tlsCfg, cfg)
			},
		}
		closeH3 := func() error {
			cancelHandshake()
			return errors.Join(tr.Close(), qtr.Close(), pc.Close())
		}
		success := false
		defer func() {
			if !success {
				stopTimer()
				_ = closeH3()
			}
		}()
		pr, pw := io.Pipe()
		req, e := http.NewRequestWithContext(cctx, http.MethodConnect, u, pr)
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
		if e := finishCONNECTHandshake(cctx, stopTimer, pw, resp); e != nil {
			return e
		}
		success = true
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
		return nil, err
	}
	return conn, nil
}
