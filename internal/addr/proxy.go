package addr

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// PROXY / PROXY-CONNECT:proxy:targethost:targetport[,proxyport=N][,crlf][,http-version=1.0]
// Classic HTTP CONNECT through a proxy server.
func openProxyConnect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	// Params: proxyhost, targethost, targetport  (or combined from parser)
	proxyHost, targetHost, targetPort, err := proxyParams(s)
	if err != nil {
		return nil, err
	}
	proxyPort := s.OptionValue("proxyport", "8080")
	if proxyPort == "" {
		proxyPort = "8080"
	}
	ver := s.OptionValue("http-version", "1.0")
	if ver == "" {
		ver = "1.0"
	}
	// crlf option: classic default for PROXY is CRLF line ends
	useCRLF := !s.HasOption("crlf") || s.BoolOption("crlf")
	nl := "\n"
	if useCRLF {
		nl = "\r\n"
	}

	addr := net.JoinHostPort(stripBrackets(proxyHost), proxyPort)
	d := net.Dialer{Timeout: connectTimeout(s)}
	var conn net.Conn
	err = withRetry(ctx, s, g, "PROXY-CONNECT", func() error {
		c, e := d.DialContext(ctx, "tcp", addr)
		if e != nil {
			return e
		}
		// CONNECT host:port HTTP/1.x
		req := fmt.Sprintf("CONNECT %s:%s HTTP/%s%s", stripBrackets(targetHost), targetPort, ver, nl)
		// Optional proxy-authorization: user:pass (base64) — leave for later
		req += nl // end headers
		if _, e := c.Write([]byte(req)); e != nil {
			c.Close()
			return e
		}
		br := bufio.NewReader(c)
		status, e := br.ReadString('\n')
		if e != nil {
			c.Close()
			return fmt.Errorf("proxy response: %w", e)
		}
		// HTTP/1.x 200 ...
		if !strings.Contains(status, " 200") {
			c.Close()
			return fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(status))
		}
		// Drain headers until blank line
		for {
			line, e := br.ReadString('\n')
			if e != nil {
				c.Close()
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
	if err != nil {
		return nil, err
	}
	rememberAddrs(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = mode
	return &Opened{Stream: st, Label: "PROXY:" + targetHost + ":" + targetPort}, nil
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
