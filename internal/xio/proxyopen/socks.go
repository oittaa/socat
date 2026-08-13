package proxyopen

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// SOCKS4 / SOCKS4A:sockshost:targethost:targetport[,socksport=N][,socksuser=U]
func openSOCKS4Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS4(ctx, s, mode, g, false)
}

func openSOCKS4AConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS4(ctx, s, mode, g, true)
}

func openSOCKS4(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, socks4a bool) (*xio.Opened, error) {
	socksHost, socksPort, targetHost, targetPort, err := socksParams(s)
	if err != nil {
		return nil, err
	}
	user := s.OptionValue("socksuser", "")
	if user == "" {
		user = "nobody"
	}

	portNum, err := xio.ResolvePortNum("tcp", targetPort)
	if err != nil {
		return nil, fmt.Errorf("socks target port: %w", err)
	}

	// SOCKS4A (classic xio-socks.c): dest IP is always 0.0.0.1 and the
	// hostname is appended after the userid NUL. Do not resolve the target.
	// SOCKS4: resolve target to xio.IPv4; no hostname trailer.
	var ip4 [4]byte
	hostName := xio.StripBrackets(targetHost)
	if socks4a {
		ip4 = [4]byte{0, 0, 0, 1}
	} else if ip := net.ParseIP(hostName); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("SOCKS4 requires xio.IPv4 target (got %s)", targetHost)
		}
		copy(ip4[:], v4)
	} else {
		ips, e := net.LookupIP(hostName)
		if e == nil {
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					copy(ip4[:], v4)
					break
				}
			}
		}
		if ip4 == [4]byte{} {
			return nil, fmt.Errorf("SOCKS4: cannot resolve %s to xio.IPv4", targetHost)
		}
	}

	addr := net.JoinHostPort(xio.StripBrackets(socksHost), socksPort)
	network := xio.ConnectNetworkForType(g, s, socksHost, "tcp")
	d := net.Dialer{Timeout: xio.ConnectTimeout(s)}
	label := fmt.Sprintf("SOCKS4:%s:%s", targetHost, targetPort)
	if socks4a {
		label = fmt.Sprintf("SOCKS4A:%s:%s", targetHost, targetPort)
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		e := xio.WithRetry(dctx, s, g, "SOCKS4", func() error {
			c, e := d.DialContext(dctx, network, addr)
			if e != nil {
				return e
			}
			req := make([]byte, 0, 8+len(user)+2+len(hostName)+1)
			req = append(req, 4, 1) // VN=4, CD=CONNECT
			req = binary.BigEndian.AppendUint16(req, uint16(portNum))
			req = append(req, ip4[:]...)
			req = append(req, []byte(user)...)
			req = append(req, 0) // userid NUL
			if socks4a {
				req = append(req, []byte(hostName)...)
				req = append(req, 0)
			}
			if _, e := c.Write(req); e != nil {
				c.Close()
				return e
			}
			var resp [8]byte
			if _, e := io.ReadFull(c, resp[:]); e != nil {
				c.Close()
				return fmt.Errorf("socks4 reply: %w", e)
			}
			if resp[1] != 90 {
				c.Close()
				return fmt.Errorf("socks4 rejected (cd=%d)", resp[1])
			}
			conn = c
			return nil
		})
		return conn, e
	}

	wrap := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}

	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := xio.ParsePositiveInt(v); e == nil {
			maxChildren = n
		}
	}
	if maxChildren > 0 && !fork {
		return nil, fmt.Errorf("%s: option max-children not allowed without option fork", s.Type)
	}
	if fork {
		return &xio.Opened{
			ConnectFork: true,
			Fork:        true,
			MaxChildren: maxChildren,
			Interval:    xio.ParseRetry(s).Interval,
			Label:       label,
			Dial:        dialOnce,
			WrapDial:    wrap,
		}, nil
	}

	conn, err := dialOnce(ctx)
	if err != nil {
		return nil, err
	}
	xio.RememberAddrs(g, conn)
	st, err := wrap(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = mode
	return &xio.Opened{Stream: st, Label: label}, nil
}

// SOCKS5 / SOCKS5-CONNECT:sockshost:targethost:targetport[,socksport=N]
// Also SOCKS5-CONNECT:server:socksport:target:port (4 params).
func openSOCKS5Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	socksHost, socksPort, targetHost, targetPort, err := socksParams(s)
	if err != nil {
		return nil, err
	}
	user := s.OptionValue("socksuser", "")
	pass := s.OptionValue("sockspass", "")
	if pass == "" {
		pass = s.OptionValue("sockspassword", "")
	}

	portNum, err := xio.ResolvePortNum("tcp", targetPort)
	if err != nil {
		return nil, fmt.Errorf("socks5 target port: %w", err)
	}

	var atyp byte
	var addrBytes []byte
	if ip := net.ParseIP(xio.StripBrackets(targetHost)); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			atyp = 1
			addrBytes = append([]byte(nil), v4...)
		} else {
			atyp = 4
			addrBytes = append([]byte(nil), ip.To16()...)
		}
	} else {
		h := xio.StripBrackets(targetHost)
		if len(h) > 255 {
			return nil, fmt.Errorf("socks5: domain name too long")
		}
		atyp = 3
		addrBytes = append([]byte{byte(len(h))}, []byte(h)...)
	}

	addr := net.JoinHostPort(xio.StripBrackets(socksHost), socksPort)
	network := xio.ConnectNetworkForType(g, s, socksHost, "tcp")
	d := net.Dialer{Timeout: xio.ConnectTimeout(s)}
	label := fmt.Sprintf("SOCKS5:%s:%s", targetHost, targetPort)

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		e := xio.WithRetry(dctx, s, g, "SOCKS5", func() error {
			c, e := d.DialContext(dctx, network, addr)
			if e != nil {
				return e
			}
			methods := []byte{0}
			if user != "" {
				methods = []byte{0, 2}
			}
			greet := append([]byte{5, byte(len(methods))}, methods...)
			if _, e := c.Write(greet); e != nil {
				c.Close()
				return e
			}
			var hello [2]byte
			if _, e := io.ReadFull(c, hello[:]); e != nil {
				c.Close()
				return fmt.Errorf("socks5 hello: %w", e)
			}
			if hello[0] != 5 {
				c.Close()
				return fmt.Errorf("socks5: bad version %d", hello[0])
			}
			switch hello[1] {
			case 0:
			case 2:
				if user == "" {
					c.Close()
					return fmt.Errorf("socks5: server requires username/password")
				}
				if len(user) > 255 || len(pass) > 255 {
					c.Close()
					return fmt.Errorf("socks5: credentials too long")
				}
				auth := []byte{1, byte(len(user))}
				auth = append(auth, []byte(user)...)
				auth = append(auth, byte(len(pass)))
				auth = append(auth, []byte(pass)...)
				if _, e := c.Write(auth); e != nil {
					c.Close()
					return e
				}
				var aresp [2]byte
				if _, e := io.ReadFull(c, aresp[:]); e != nil {
					c.Close()
					return fmt.Errorf("socks5 auth reply: %w", e)
				}
				if aresp[1] != 0 {
					c.Close()
					return fmt.Errorf("socks5 auth failed (status=%d)", aresp[1])
				}
			case 0xff:
				c.Close()
				return fmt.Errorf("socks5: no acceptable auth method")
			default:
				c.Close()
				return fmt.Errorf("socks5: unsupported auth method %d", hello[1])
			}

			req := []byte{5, 1, 0, atyp}
			req = append(req, addrBytes...)
			req = binary.BigEndian.AppendUint16(req, uint16(portNum))
			if _, e := c.Write(req); e != nil {
				c.Close()
				return e
			}
			var hdr [4]byte
			if _, e := io.ReadFull(c, hdr[:]); e != nil {
				c.Close()
				return fmt.Errorf("socks5 reply: %w", e)
			}
			if hdr[0] != 5 {
				c.Close()
				return fmt.Errorf("socks5: bad reply version %d", hdr[0])
			}
			if hdr[1] != 0 {
				c.Close()
				return fmt.Errorf("socks5 connect failed (rep=%d)", hdr[1])
			}
			switch hdr[3] {
			case 1:
				var skip [6]byte
				if _, e := io.ReadFull(c, skip[:]); e != nil {
					c.Close()
					return e
				}
			case 4:
				var skip [18]byte
				if _, e := io.ReadFull(c, skip[:]); e != nil {
					c.Close()
					return e
				}
			case 3:
				var ln [1]byte
				if _, e := io.ReadFull(c, ln[:]); e != nil {
					c.Close()
					return e
				}
				skip := make([]byte, int(ln[0])+2)
				if _, e := io.ReadFull(c, skip); e != nil {
					c.Close()
					return e
				}
			default:
				c.Close()
				return fmt.Errorf("socks5: unknown atyp %d in reply", hdr[3])
			}
			conn = c
			return nil
		})
		return conn, e
	}

	wrap := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}

	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := xio.ParsePositiveInt(v); e == nil {
			maxChildren = n
		}
	}
	if maxChildren > 0 && !fork {
		return nil, fmt.Errorf("%s: option max-children not allowed without option fork", s.Type)
	}
	if fork {
		return &xio.Opened{
			ConnectFork: true,
			Fork:        true,
			MaxChildren: maxChildren,
			Interval:    xio.ParseRetry(s).Interval,
			Label:       label,
			Dial:        dialOnce,
			WrapDial:    wrap,
		}, nil
	}

	conn, err := dialOnce(ctx)
	if err != nil {
		return nil, err
	}
	xio.RememberAddrs(g, conn)
	st, err := wrap(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = mode
	return &xio.Opened{Stream: st, Label: label}, nil
}

// socksParams parses SOCKS address params.
// Forms:
//
//	server host port
//	server:host:port  (via split)
//	server sport host port  (4 params; sport used if socksport option unset)
func socksParams(s parse.Spec) (socksHost, socksPort, targetHost, targetPort string, err error) {
	socksPort = s.OptionValue("socksport", "")
	p := s.Params
	if len(p) >= 4 {
		// server, socks-port, target-host, target-port
		if socksPort == "" {
			socksPort = p[1]
		}
		return p[0], defaultSocksPort(socksPort), p[2], p[3], nil
	}
	if len(p) >= 3 {
		return p[0], defaultSocksPort(socksPort), p[1], p[2], nil
	}
	if len(p) == 2 {
		h, pt, e := net.SplitHostPort(p[1])
		if e == nil {
			return p[0], defaultSocksPort(socksPort), h, pt, nil
		}
	}
	return "", "", "", "", fmt.Errorf("%s requires socks-server, host, and port", s.Type)
}

func defaultSocksPort(p string) string {
	if p == "" {
		return "1080"
	}
	return p
}
