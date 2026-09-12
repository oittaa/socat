package proxyopen

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

// SOCKS4 / SOCKS4A:sockshost:targethost:targetport[,socksport=N][,socksuser=U]
func openSOCKS4Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS4(ctx, s, mode, g, false)
}

func openSOCKS4AConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS4(ctx, s, mode, g, true)
}

func openSOCKS4(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global, socks4a bool) (*xio.Opened, error) {
	if err := tlsopen.RejectHiddenTLSOnPlaintext(s.Type, s.TLS); err != nil {
		return nil, err
	}
	if !s.Proxy.EndpointsSet {
		return nil, fmt.Errorf("%s requires socks-server, host, and port", s.Type)
	}
	user := socksUser(s.Proxy)

	portNum, err := xio.ResolvePort("tcp", s.Proxy.TargetPort)
	if err != nil {
		return nil, fmt.Errorf("socks target port: %w", err)
	}

	ip4, err := socks4DestIP(ctx, s, s.Proxy.Target, socks4a)
	if err != nil {
		return nil, err
	}
	hostName := s.Proxy.Target.String()

	network := xio.ConnectNetworkForType(g, s, s.Proxy.Server, "tcp")
	timeout := xio.ConnectTimeout(s)
	handshakeTimeout := xio.HandshakeTimeout(s)
	label := fmt.Sprintf("SOCKS4:%s:%s", s.Proxy.Target.Original(), s.Proxy.TargetPort.Text())
	if socks4a {
		label = fmt.Sprintf("SOCKS4A:%s:%s", s.Proxy.Target.Original(), s.Proxy.TargetPort.Text())
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		e := xio.WithRetry(dctx, g, s.Common.Retry.Policy(), "SOCKS4", func() error {
			c, e := xio.DialTCPAll(dctx, xio.DialTarget{Network: network, Host: s.Proxy.Server, Port: socksPortTarget(s.Proxy)}, s, g, timeout, nil)
			if e != nil {
				return e
			}
			e = xio.WithHandshakeDeadline(c, handshakeTimeout, func() error {
				return socks4Handshake(c, socks4a, user, hostName, ip4, portNum)
			})
			if e != nil {
				logx.CloseQuiet(c)
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
			return xio.SetupConnectedStream(s, relay.NetStream{Conn: c})
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
	return socks4ReadReply(c)
}

func socks4ReadReply(r io.Reader) error {
	var resp [8]byte
	if _, err := io.ReadFull(r, resp[:]); err != nil {
		return fmt.Errorf("socks4 reply: %w", err)
	}
	if resp[1] != 90 {
		return fmt.Errorf("socks4 rejected (cd=%d)", resp[1])
	}
	return nil
}

func socks4DestIP(ctx context.Context, s addrconfig.Address, target addrconfig.HostTarget, socks4a bool) ([4]byte, error) {
	if socks4a {
		return [4]byte{0, 0, 0, 1}, nil
	}
	if target.IsLiteral() {
		v4 := target.IP().To4()
		if v4 == nil {
			return [4]byte{}, fmt.Errorf("SOCKS4 requires IPv4 target (got %s)", target.Original())
		}
		var ip4 [4]byte
		copy(ip4[:], v4)
		return ip4, nil
	}
	ips, err := xio.LookupIP(ctx, s, "ip4", target.String())
	if err != nil {
		return [4]byte{}, fmt.Errorf("SOCKS4: resolve %s: %w", target.Original(), err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			var ip4 [4]byte
			copy(ip4[:], v4)
			return ip4, nil
		}
	}
	return [4]byte{}, fmt.Errorf("SOCKS4: cannot resolve %s to IPv4", target.Original())
}

func socksUser(proxy addrconfig.Proxy) string {
	if proxy.SOCKSUser.Set && proxy.SOCKSUser.Value != "" {
		return proxy.SOCKSUser.Value
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
func openSOCKS5Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS5(ctx, s, mode, g, socks5CmdConnect)
}

// SOCKS5-LISTEN / SOCKS5-BIND: RFC 1928 BIND via the SOCKS server.
func openSOCKS5Listen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSOCKS5(ctx, s, mode, g, socks5CmdBind)
}

func openSOCKS5(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global, cmd byte) (*xio.Opened, error) {
	if err := tlsopen.RejectHiddenTLSOnPlaintext(s.Type, s.TLS); err != nil {
		return nil, err
	}
	if !s.Proxy.EndpointsSet {
		return nil, fmt.Errorf("%s requires socks-server, host, and port", s.Type)
	}
	auth := socks5Credentials(s.Proxy)
	if auth.OfferUserPass && g != nil && g.Log != nil {
		if !s.Proxy.SOCKSUser.Set {
			g.Log.Warningf("SOCKS5 password without username, falling back to \"anonymous\"")
		}
		if !s.Proxy.SOCKSPassword.Set {
			g.Log.Warningf("SOCKS5 username without password")
		}
	}

	portNum, err := xio.ResolvePort("tcp", s.Proxy.TargetPort)
	if err != nil {
		return nil, fmt.Errorf("socks5 target port: %w", err)
	}

	dest, err := socks5DestFromTarget(s.Proxy.Target, portNum)
	if err != nil {
		return nil, err
	}

	network := xio.ConnectNetworkForType(g, s, s.Proxy.Server, "tcp")
	timeout := xio.ConnectTimeout(s)
	handshakeTimeout := xio.HandshakeTimeout(s)
	label := fmt.Sprintf("SOCKS5:%s:%s", s.Proxy.Target.Original(), s.Proxy.TargetPort.Text())
	if cmd == socks5CmdBind {
		label = fmt.Sprintf("SOCKS5-LISTEN:%s:%s", s.Proxy.Target.Original(), s.Proxy.TargetPort.Text())
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		e := xio.WithRetry(dctx, g, s.Common.Retry.Policy(), "SOCKS5", func() error {
			c, e := xio.DialTCPAll(dctx, xio.DialTarget{Network: network, Host: s.Proxy.Server, Port: socksPortTarget(s.Proxy)}, s, g, timeout, nil)
			if e != nil {
				return e
			}
			if e := xio.WithHandshakeDeadline(c, handshakeTimeout, func() error {
				return socks5Handshake(c, cmd, dest, auth)
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
			return xio.SetupConnectedStream(s, relay.NetStream{Conn: c})
		},
	})
}

func socks5DestFromTarget(target addrconfig.HostTarget, portNum int) (socks5Dest, error) {
	dest := socks5Dest{Port: portNum}
	if target.IsLiteral() {
		ip := target.IP()
		if v4 := ip.To4(); v4 != nil {
			dest.AddrType = 1
			dest.Addr = append([]byte(nil), v4...)
			return dest, nil
		}
		dest.AddrType = 4
		dest.Addr = append([]byte(nil), ip.To16()...)
		return dest, nil
	}
	h := target.String()
	n, ok := xio.Uint8FromInt(len(h))
	if !ok {
		return socks5Dest{}, fmt.Errorf("socks5: domain name too long")
	}
	dest.AddrType = 3
	dest.Addr = append([]byte{n}, []byte(h)...)
	return dest, nil
}

func socksPortTarget(p addrconfig.Proxy) addrconfig.PortTarget {
	if p.SOCKSPortSet && !p.SOCKSPort.Empty() {
		return p.SOCKSPort
	}
	return addrconfig.PortFromText("1080")
}

// socks5Credentials: if socksuser or sockspass is set, offer username/password
// in addition to no-auth. sockspass without socksuser uses user "anonymous";
// socksuser without sockspass uses an empty password.
// Empty credentials with OfferUserPass set are distinct from offering no auth.
func socks5Credentials(proxy addrconfig.Proxy) socks5Auth {
	if !proxy.SOCKSUser.Set && !proxy.SOCKSPassword.Set {
		return socks5Auth{}
	}
	auth := socks5Auth{OfferUserPass: true}
	if proxy.SOCKSUser.Set {
		auth.User = proxy.SOCKSUser.Value
	} else {
		auth.User = "anonymous"
	}
	if proxy.SOCKSPassword.Set {
		auth.Pass = proxy.SOCKSPassword.Value
	}
	return auth
}

// socks5AuthMethods is the RFC 1928 method list: always no-auth (method 0)
// and, with credentials, also username/password (method 2): 05 02 00 02.
// Do not drop method 0.
func socks5AuthMethods(offerUserPass bool) []byte {
	if offerUserPass {
		return []byte{0, 2}
	}
	return []byte{0}
}

// socks5Dest is the RFC 1928 CONNECT/BIND target (ATYP, encoded address, port).
type socks5Dest struct {
	AddrType byte
	Addr     []byte
	Port     int
}

// socks5Auth is the username/password method we offer the server.
// OfferUserPass false means no-auth only. Empty User/Pass with OfferUserPass
// true is still an offered method, not "no authentication".
type socks5Auth struct {
	User          string
	Pass          string
	OfferUserPass bool
}

func socks5Handshake(c net.Conn, cmd byte, dest socks5Dest, auth socks5Auth) (err error) {
	defer func() {
		if err != nil {
			logx.CloseQuiet(c)
		}
	}()
	methods := socks5AuthMethods(auth.OfferUserPass)
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
		// Accept no-auth even when method 2 was also offered.
	case 2:
		if !auth.OfferUserPass {
			return fmt.Errorf("socks5: authentication with SOCKS5 server failed")
		}
		ulen, uok := xio.Uint8FromInt(len(auth.User))
		plen, pok := xio.Uint8FromInt(len(auth.Pass))
		if !uok || !pok {
			return fmt.Errorf("socks5: credentials too long")
		}
		authReq := []byte{1, ulen}
		authReq = append(authReq, []byte(auth.User)...)
		authReq = append(authReq, plen)
		authReq = append(authReq, []byte(auth.Pass)...)
		if _, err = c.Write(authReq); err != nil {
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

	port, ok := xio.Uint16FromInt(dest.Port)
	if !ok {
		return fmt.Errorf("socks5: invalid port %d", dest.Port)
	}
	req := []byte{5, cmd, 0, dest.AddrType}
	req = append(req, dest.Addr...)
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

func socks5ReadReply(c io.Reader) error {
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
