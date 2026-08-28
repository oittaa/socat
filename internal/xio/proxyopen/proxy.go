package proxyopen

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

const maxHTTP1ProxyResponseBytes = 64 << 10

// PROXY / PROXY-CONNECT:proxy:targethost:targetport[,proxyport=N][,http-version=1.0|2|3][,resolve]
// HTTP CONNECT through a proxy. Default is classic HTTP/1.0.
func openProxyConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Params: proxyhost, targethost, targetport  (or combined from parser)
	proxyHost, targetHost, targetPort, err := proxyParams(s)
	if err != nil {
		return nil, err
	}
	proxyPort := s.OptionValue("proxyport", "8080")
	if proxyPort == "" {
		proxyPort = "8080"
	}
	major, err := parseHTTPVersion(s)
	if err != nil {
		return nil, err
	}
	if s.BoolOption("h2c") && major != httpVer2 {
		return nil, fmt.Errorf("h2c requires http-version=2")
	}
	// ignorecr is HTTP/1 CONNECT response parsing only (classic xio-proxy.c).
	// HTTP/2 and HTTP/3 have no CRLF status/header reader, so an enabled
	// ignorecr would be a silent no-op. Reject it instead.
	if s.BoolOption("ignorecr") && major != httpVer1 {
		return nil, fmt.Errorf("ignorecr applies only to HTTP/1 CONNECT responses")
	}
	ver := s.OptionValue("http-version", "1.0")
	if ver == "" {
		ver = "1.0"
	}

	// Classic proxy-resolve / resolve (default true): put IPv4 in CONNECT target.
	// proxyecho.sh and many proxies expect "CONNECT a.b.c.d:port HTTP/x.y".
	connectHost := xio.StripBrackets(targetHost)
	doResolve := true
	if s.HasOption("proxy-resolve") {
		doResolve = s.BoolOption("proxy-resolve")
	} else if s.HasOption("resolve") {
		doResolve = s.BoolOption("resolve")
	}
	if doResolve {
		if ip := net.ParseIP(connectHost); ip == nil {
			ips, resolveErr := xio.LookupResolver(s).LookupIP(ctx, "ip4", connectHost)
			if resolveErr != nil {
				return nil, fmt.Errorf("PROXY: resolve target %s: %w", targetHost, resolveErr)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("PROXY: resolve target %s: no IPv4 addresses", targetHost)
			}
			connectHost = ips[0].String()
		} else if ip4 := ip.To4(); ip4 != nil {
			connectHost = ip4.String()
		}
	}

	t := proxyTarget{
		proxyHost:   proxyHost,
		proxyPort:   proxyPort,
		targetHost:  targetHost,
		targetPort:  targetPort,
		connectHost: connectHost,
		label:       "PROXY:" + targetHost + ":" + targetPort,
	}
	switch major {
	case httpVer2:
		return openProxyDial(ctx, s, mode, g, t, true, func(dctx context.Context) (net.Conn, error) {
			return dialH2CONNECT(dctx, s, g, t)
		})
	case httpVer3:
		return openProxyDial(ctx, s, mode, g, t, true, func(dctx context.Context) (net.Conn, error) {
			return dialH3CONNECT(dctx, s, g, t)
		})
	}

	// Honour pf=ip4/ip6 when dialing the proxy host.
	network := xio.ConnectNetworkForType(g, s, proxyHost, "tcp")
	timeout := xio.ConnectTimeout(s)
	handshakeTimeout := xio.HandshakeTimeout(s)

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		e := xio.WithRetry(dctx, s, g, "PROXY-CONNECT", func() error {
			c, e := xio.DialTCPAll(dctx, network, xio.StripBrackets(proxyHost), proxyPort, s, g, timeout, nil)
			if e != nil {
				return e
			}
			var negotiated net.Conn
			e = xio.WithHandshakeDeadline(c, handshakeTimeout, func() error {
				var handshakeErr error
				negotiated, handshakeErr = proxyHTTP1Handshake(c, s, connectHost, targetPort, ver)
				return handshakeErr
			})
			if e != nil {
				logx.CloseQuiet(c)
				return e
			}
			conn = negotiated
			return nil
		})
		return conn, e
	}

	return openProxyDial(ctx, s, mode, g, t, false, dialOnce)
}

func proxyHTTP1Handshake(c net.Conn, s parse.Spec, connectHost, targetPort, version string) (net.Conn, error) {
	// CONNECT host:port HTTP/1.x\r\n[auth]\r\n  (classic always CRLF, even with ignorecr)
	req := fmt.Sprintf("CONNECT %s HTTP/%s\r\n", net.JoinHostPort(connectHost, targetPort), version)
	auth, err := proxyAuthHeader(s)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		req += auth
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return nil, err
	}
	// ignorecr is classic TYPE_BOOL GROUP_HTTP PH_LATE (xio-proxy.c opt_ignorecr
	// / retropt_bool). tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba and
	// official master af5388c898c7bb60997935aee93c223deba60c4a are the same
	// parser: LF terminates a response line, and CR is ignored while reading
	// the answer. doc/socat.yo presents a flag without [=<bool>]; the C type is
	// BOOL, so this port uses BoolOption (bare / =1 enable, =0 disable; last
	// occurrence wins). Requests still use CR+NL.
	ignoreCR := s.BoolOption("ignorecr")
	br := bufio.NewReaderSize(c, maxHTTP1ProxyResponseBytes+1)
	total := 0
	status, err := readProxyResponseLine(br, &total, ignoreCR)
	if err != nil {
		return nil, fmt.Errorf("proxy response: %w", err)
	}
	// Classic: accept HTTP/1.0 or 1.1, skip multiple spaces, require code 200.
	if !proxyStatusOK(status) {
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(status))
	}
	// Drain headers until blank line.
	for {
		line, err := readProxyResponseLine(br, &total, ignoreCR)
		if err != nil {
			return nil, err
		}
		if proxyHTTP1BlankLine(line) {
			break
		}
	}
	// Any buffered bytes after headers must remain available to the stream.
	if br.Buffered() == 0 {
		return c, nil
	}
	peek, _ := br.Peek(br.Buffered())
	buffered := append([]byte(nil), peek...)
	_, _ = br.Discard(br.Buffered())
	return &prefixConn{Conn: c, prefix: buffered}, nil
}

func readProxyResponseLine(br *bufio.Reader, total *int, ignoreCR bool) (string, error) {
	// ReadSlice('\n') keeps classic byte-at-a-time CR-then-LF behavior: a
	// lone CR stays buffered until LF arrives on a later read.
	line, err := br.ReadSlice('\n')
	*total += len(line)
	if *total > maxHTTP1ProxyResponseBytes {
		return "", fmt.Errorf("proxy response headers exceed %d bytes", maxHTTP1ProxyResponseBytes)
	}
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("proxy response header line exceeds %d bytes", maxHTTP1ProxyResponseBytes)
	}
	if err != nil {
		return string(line), err
	}
	if ignoreCR {
		return string(bytes.ReplaceAll(line, []byte{'\r'}, nil)), nil
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return "", fmt.Errorf("proxy response line is not CRLF-terminated (use ignorecr to allow LF)")
	}
	return string(line), nil
}

func proxyHTTP1BlankLine(line string) bool {
	return line == "\r\n" || line == "\n"
}

type proxyTarget struct {
	proxyHost, proxyPort   string
	targetHost, targetPort string
	connectHost            string
	label                  string
}

func openProxyDial(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, t proxyTarget, transportLifecycleApplied bool, dialOnce func(context.Context) (net.Conn, error)) (*xio.Opened, error) {
	_ = mode
	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: t.label,
		Dial:  dialOnce,
		Wrap: func(c net.Conn) (relay.Stream, error) {
			if transportLifecycleApplied {
				return xio.WrapCommonAfterConnectedFDLifecycleApplied(s, relay.NetStream{Conn: c})
			}
			return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
		},
	})
}

// proxyAuthHeader returns classic "Proxy-authorization: Basic …\r\n" or "".
func proxyAuthHeader(s parse.Spec) (string, error) {
	raw, err := proxyAuthString(s)
	if err != nil || raw == "" {
		return "", err
	}
	return "Proxy-authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(raw)) + "\r\n", nil
}

func proxyAuthString(s parse.Spec) (string, error) {
	inline := ""
	if o, ok := s.OptionNamed("proxy-authorization"); ok && o.Has {
		inline = o.Value
	}
	file := ""
	if o, ok := s.OptionNamed("proxy-authorization-file"); ok && o.Has {
		file = o.Value
	}
	if inline != "" && file != "" {
		return "", fmt.Errorf("only one of options proxy-authorization and proxy-authorization-file allowed")
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("open(%q, O_RDONLY): %w", file, err)
		}
		return string(b), nil
	}
	return inline, nil
}

// proxyStatusOK matches classic xio-proxy.c: HTTP/1.0|1.1, skip spaces, "200".
func proxyStatusOK(status string) bool {
	line := strings.TrimRight(status, "\r\n")
	var rest string
	switch {
	case strings.HasPrefix(line, "HTTP/1.0 "):
		rest = line[len("HTTP/1.0 "):]
	case strings.HasPrefix(line, "HTTP/1.1 "):
		rest = line[len("HTTP/1.1 "):]
	default:
		// Also accept HTTP/1.x with extra spaces after version (PROXY2SPACES style
		// puts spaces between version and code: "HTTP/1.0   200").
		if !strings.HasPrefix(line, "HTTP/1.") {
			return false
		}
		// Find first space after "HTTP/1.x"
		i := strings.IndexByte(line, ' ')
		if i < 0 {
			return false
		}
		rest = line[i+1:]
	}
	rest = strings.TrimLeft(rest, " ")
	if len(rest) < 3 {
		return false
	}
	code := rest[:3]
	if _, err := strconv.Atoi(code); err != nil {
		return false
	}
	return code == "200"
}

func proxyParams(s parse.Spec) (proxy, host, port string, err error) {
	// PROXY:proxy:host:port → params may be split by our parser
	p := s.Params
	if len(p) >= 3 {
		return p[0], p[1], p[2], nil
	}
	if len(p) == 1 {
		// single string "proxy:host:port" unlikely
		parts := strings.Split(p[0], ":")
		if len(parts) >= 3 {
			return parts[0], parts[1], parts[2], nil
		}
	}
	if len(p) == 2 {
		// proxyhost, host:port
		h, pt, e := net.SplitHostPort(p[1])
		if e == nil {
			return p[0], h, pt, nil
		}
	}
	return "", "", "", fmt.Errorf("%s requires proxy, host, and port", s.Type)
}

// prefixConn prepends buffered bytes to the first Read.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
