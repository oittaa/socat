package proxyopen

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

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
	ver := s.OptionValue("http-version", "1.0")
	if ver == "" {
		ver = "1.0"
	}

	// Classic proxy-resolve / resolve (default true): put xio.IPv4 in CONNECT target.
	// proxyecho.sh and many proxies expect "CONNECT a.b.c.d:port HTTP/x.y".
	connectHost := xio.StripBrackets(targetHost)
	doResolve := true
	if s.HasOption("proxy-resolve") {
		doResolve = s.BoolOption("proxy-resolve")
	} else if s.HasOption("resolve") {
		doResolve = s.BoolOption("resolve")
	}
	if doResolve {
		if ip := net.ParseIP(connectHost); ip == nil || ip.To4() == nil {
			if ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", connectHost); e == nil && len(ips) > 0 {
				connectHost = ips[0].String()
			}
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
		return openProxyDial(ctx, s, mode, g, t, func(dctx context.Context) (net.Conn, error) {
			return dialH2CONNECT(dctx, s, g, t)
		})
	case httpVer3:
		return openProxyDial(ctx, s, mode, g, t, func(dctx context.Context) (net.Conn, error) {
			return dialH3CONNECT(dctx, s, g, t)
		})
	}

	addr := net.JoinHostPort(xio.StripBrackets(proxyHost), proxyPort)
	// Honour pf=ip4/ip6 when dialing the proxy host.
	network := xio.ConnectNetworkForType(g, s, proxyHost, "tcp")
	d := net.Dialer{Timeout: xio.ConnectTimeout(s)}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		e := xio.WithRetry(dctx, s, g, "PROXY-CONNECT", func() error {
			c, e := d.DialContext(dctx, network, addr)
			if e != nil {
				return e
			}
			// CONNECT host:port HTTP/1.x\r\n[auth]\r\n  (classic always CRLF)
			req := fmt.Sprintf("CONNECT %s:%s HTTP/%s\r\n", connectHost, targetPort, ver)
			if auth, e := proxyAuthHeader(s); e != nil {
				_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				return e
			} else if auth != "" {
				req += auth
			}
			req += "\r\n"
			if _, e := c.Write([]byte(req)); e != nil {
				_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				return e
			}
			br := bufio.NewReader(c)
			status, e := br.ReadString('\n')
			if e != nil {
				_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				return fmt.Errorf("proxy response: %w", e)
			}
			// Classic: accept HTTP/1.0 or 1.1, skip multiple spaces, require code 200.
			if !proxyStatusOK(status) {
				_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				return fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(status))
			}
			// Drain headers until blank line
			for {
				line, e := br.ReadString('\n')
				if e != nil {
					_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
					return e
				}
				if line == "\r\n" || line == "\n" {
					break
				}
			}
			// Any buffered bytes after headers must remain available to the stream.
			if br.Buffered() > 0 {
				peek, _ := br.Peek(br.Buffered())
				conn = &prefixConn{Conn: c, prefix: append([]byte(nil), peek...)}
				_, _ = br.Discard(br.Buffered())
			} else {
				conn = c
			}
			return nil
		})
		return conn, e
	}

	return openProxyDial(ctx, s, mode, g, t, dialOnce)
}

type proxyTarget struct {
	proxyHost, proxyPort   string
	targetHost, targetPort string
	connectHost            string
	label                  string
}

func openProxyDial(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, t proxyTarget, dialOnce func(context.Context) (net.Conn, error)) (*xio.Opened, error) {
	_ = mode
	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: t.label,
		Dial:  dialOnce,
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommon(s, relay.NetStream{Conn: c})
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
