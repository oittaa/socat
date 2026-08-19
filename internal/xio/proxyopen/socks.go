package proxyopen

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

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
	user := socksUser(s)

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
		ips, e := xio.LookupResolver(s).LookupIP(ctx, "ip4", hostName)
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
	handshakeTimeout := xio.HandshakeTimeout(s)
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
			e = xio.WithHandshakeDeadline(c, handshakeTimeout, func() error {
				return socks4Handshake(c, socks4a, user, hostName, ip4, portNum)
			})
			if e != nil {
				_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				return e
			}
			conn = c
			return nil
		})
		return conn, e
	}

	_ = mode
	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: label,
		Dial:  dialOnce,
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommon(s, relay.NetStream{Conn: c})
		},
	})
}

func socks4Handshake(c net.Conn, socks4a bool, user, hostName string, ip4 [4]byte, portNum int) error {
	req := make([]byte, 0, 8+len(user)+2+len(hostName)+1)
	port, ok := xio.Uint16FromInt(portNum)
	if !ok {
		return fmt.Errorf("socks4: invalid port %d", portNum)
	}
	req = append(req, 4, 1) // VN=4, CD=CONNECT
	req = binary.BigEndian.AppendUint16(req, port)
	req = append(req, ip4[:]...)
	req = append(req, []byte(user)...)
	req = append(req, 0) // userid NUL
	if socks4a {
		req = append(req, []byte(hostName)...)
		req = append(req, 0)
	}
	if _, err := c.Write(req); err != nil {
		return err
	}
	var resp [8]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return fmt.Errorf("socks4 reply: %w", err)
	}
	if resp[1] != 90 {
		return fmt.Errorf("socks4 rejected (cd=%d)", resp[1])
	}
	return nil
}

func socksUser(s parse.Spec) string {
	if user := s.OptionValue("socksuser", ""); user != "" {
		return user
	}
	if user := os.Getenv("LOGNAME"); user != "" {
		return user
	}
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	return "anonymous"
}

const (
	socks5CmdConnect = 1
	socks5CmdBind    = 2
)

// SOCKS5 / SOCKS5-CONNECT:sockshost:targethost:targetport[,socksport=N]
// Also SOCKS5-CONNECT:server:socksport:target:port (4 params).
func openSOCKS5Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS5(ctx, s, mode, g, socks5CmdConnect)
}

// SOCKS5-LISTEN / SOCKS5-BIND: RFC 1928 BIND via the SOCKS server.
func openSOCKS5Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS5(ctx, s, mode, g, socks5CmdBind)
}

func openSOCKS5(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, cmd byte) (*xio.Opened, error) {
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
		n, ok := xio.Uint8FromInt(len(h))
		if !ok {
			return nil, fmt.Errorf("socks5: domain name too long")
		}
		atyp = 3
		addrBytes = append([]byte{n}, []byte(h)...)
	}

	addr := net.JoinHostPort(xio.StripBrackets(socksHost), socksPort)
	network := xio.ConnectNetworkForType(g, s, socksHost, "tcp")
	d := net.Dialer{Timeout: xio.ConnectTimeout(s)}
	handshakeTimeout := xio.HandshakeTimeout(s)
	label := fmt.Sprintf("SOCKS5:%s:%s", targetHost, targetPort)
	if cmd == socks5CmdBind {
		label = fmt.Sprintf("SOCKS5-LISTEN:%s:%s", targetHost, targetPort)
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		e := xio.WithRetry(dctx, s, g, "SOCKS5", func() error {
			c, e := d.DialContext(dctx, network, addr)
			if e != nil {
				return e
			}
			if e := xio.WithHandshakeDeadline(c, handshakeTimeout, func() error {
				return socks5Handshake(c, cmd, user, pass, atyp, addrBytes, portNum)
			}); e != nil {
				return e
			}
			conn = c
			return nil
		})
		return conn, e
	}

	_ = mode
	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: label,
		Dial:  dialOnce,
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommon(s, relay.NetStream{Conn: c})
		},
	})
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

func socks5Handshake(c net.Conn, cmd byte, user, pass string, atyp byte, addrBytes []byte, portNum int) (err error) {
	defer func() {
		if err != nil {
			_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		}
	}()
	methods := []byte{0}
	if user != "" {
		methods = []byte{0, 2}
	}
	nmethod, ok := xio.Uint8FromInt(len(methods))
	if !ok {
		return fmt.Errorf("socks5: too many auth methods")
	}
	if _, err = c.Write(append([]byte{5, nmethod}, methods...)); err != nil {
		return err
	}
	var hello [2]byte
	if _, err = io.ReadFull(c, hello[:]); err != nil {
		return fmt.Errorf("socks5 hello: %w", err)
	}
	if hello[0] != 5 {
		return fmt.Errorf("socks5: bad version %d", hello[0])
	}
	switch hello[1] {
	case 0:
	case 2:
		if user == "" {
			return fmt.Errorf("socks5: server requires username/password")
		}
		ulen, uok := xio.Uint8FromInt(len(user))
		plen, pok := xio.Uint8FromInt(len(pass))
		if !uok || !pok {
			return fmt.Errorf("socks5: credentials too long")
		}
		auth := []byte{1, ulen}
		auth = append(auth, []byte(user)...)
		auth = append(auth, plen)
		auth = append(auth, []byte(pass)...)
		if _, err = c.Write(auth); err != nil {
			return err
		}
		var aresp [2]byte
		if _, err = io.ReadFull(c, aresp[:]); err != nil {
			return fmt.Errorf("socks5 auth reply: %w", err)
		}
		if aresp[1] != 0 {
			return fmt.Errorf("socks5 auth failed (status=%d)", aresp[1])
		}
	case 0xff:
		return fmt.Errorf("socks5: no acceptable auth method")
	default:
		return fmt.Errorf("socks5: unsupported auth method %d", hello[1])
	}

	port, ok := xio.Uint16FromInt(portNum)
	if !ok {
		return fmt.Errorf("socks5: invalid port %d", portNum)
	}
	req := []byte{5, cmd, 0, atyp}
	req = append(req, addrBytes...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err = c.Write(req); err != nil {
		return err
	}
	if err = socks5ReadReply(c); err != nil {
		return err
	}
	if cmd == socks5CmdBind {
		return socks5ReadReply(c)
	}
	return nil
}

func socks5ReadReply(c net.Conn) error {
	var hdr [4]byte
	if _, e := io.ReadFull(c, hdr[:]); e != nil {
		return fmt.Errorf("socks5 reply: %w", e)
	}
	if hdr[0] != 5 {
		return fmt.Errorf("socks5: bad reply version %d", hdr[0])
	}
	if hdr[1] != 0 {
		return fmt.Errorf("socks5 request failed (rep=%d)", hdr[1])
	}
	switch hdr[3] {
	case 1:
		var skip [6]byte
		_, e := io.ReadFull(c, skip[:])
		return e
	case 4:
		var skip [18]byte
		_, e := io.ReadFull(c, skip[:])
		return e
	case 3:
		var ln [1]byte
		if _, e := io.ReadFull(c, ln[:]); e != nil {
			return e
		}
		skip := make([]byte, int(ln[0])+2)
		_, e := io.ReadFull(c, skip)
		return e
	default:
		return fmt.Errorf("socks5: unknown atyp %d in reply", hdr[3])
	}
}

func defaultSocksPort(p string) string {
	if p == "" {
		return "1080"
	}
	return p
}
