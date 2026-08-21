package netopen

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

// Classic SCTP (RFC 9260) one-to-one style: SOCK_STREAM + IPPROTO_SCTP.
// The kernel implements the association (INIT/COOKIE four-way, SACK, SHUTDOWN).
// We do not implement the packet format in userspace. The Linux wrappers
// github.com/ishidawataru/sctp and github.com/georgeyanev/go-sctp use the
// same kernel sockets; we stay on unix.Socket + our listen/connect path.

func openSCTPConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host := ""
	if len(s.Params) >= 1 {
		host = s.Params[0]
	}
	return openSCTPConnectNetwork(ctx, s, mode, g, sctpNetwork(xio.ConnectNetworkForType(g, s, host, "tcp")))
}

func openSCTP4Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPConnectNetwork(ctx, s, mode, g, "sctp4")
}

func openSCTP6Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPConnectNetwork(ctx, s, mode, g, "sctp6")
}

func openSCTPConnectNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	network = sctpNetwork(xio.ConnectNetworkForType(g, s, host, tcpNetwork(network)))
	addr := net.JoinHostPort(xio.StripBrackets(host), port)
	timeout := xio.ConnectTimeout(s)

	var setSockErr error
	var control func(network, address string, c syscall.RawConn) error
	if raw := s.OptionValue("setsockopt", ""); raw != "" {
		control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				setSockErr = xio.ApplySetsockoptFD(int(fd), raw)
			})
		}
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, network+" connect", func() error {
			setSockErr = nil
			c, e := dialSCTPAll(dctx, network, xio.StripBrackets(host), port, s, g, timeout, control)
			if e != nil {
				return e
			}
			if setSockErr != nil {
				logx.CloseQuiet(c)
				return setSockErr
			}
			conn = c
			return nil
		})
		return conn, err
	}

	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: fmt.Sprintf("%s:%s", network, addr),
		Dial:  dialOnce,
		LogOK: true,
	})
}

func openSCTPListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPListenNetwork(ctx, s, mode, g, sctpNetwork(xio.ListenNetwork(g, s)))
}

func openSCTP4Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPListenNetwork(ctx, s, mode, g, "sctp4")
}

func openSCTP6Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	netw := "sctp6"
	if s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		netw = "sctp"
	}
	return openSCTPListenNetwork(ctx, s, mode, g, netw)
}

func openSCTPListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
	if port == "" || strings.Trim(port, ":") == "" {
		return nil, fmt.Errorf("%s: invalid port %q", s.Type, port)
	}
	host := s.OptionValue("bind", "")
	if host == "" {
		switch network {
		case "sctp4":
			host = "0.0.0.0"
		case "sctp6", "sctp":
			host = "::"
		}
	}
	ln, err := listenSCTP(ctx, network, host, port, s)
	if err != nil {
		return nil, err
	}

	fork := s.BoolOption("fork")
	filter := func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) }
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxChildren = n
		}
	}
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}
	o := &xio.Opened{
		Kind:        xio.ListenKind(fork),
		Listener:    ln,
		Label:       fmt.Sprintf("%s-LISTEN:%s", network, port),
		PeerFilter:  filter,
		MaxChildren: maxChildren,
		WrapDial:    wrapConn,
	}
	o.AddCleanup(func() { logx.CloseQuiet(ln) })

	if fork {
		go func() {
			<-ctx.Done()
			logx.CloseQuiet(ln)
		}()
		return o, nil
	}

	if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s", ln.Addr())
	}
	at := xio.AcceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	}
	var conn net.Conn
	for {
		if !deadline.IsZero() {
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		type acc struct {
			c   net.Conn
			err error
		}
		ch := make(chan acc, 1)
		go func() {
			c, err := ln.Accept()
			ch <- acc{c, err}
		}()
		select {
		case <-ctx.Done():
			logx.CloseQuiet(ln)
			o.Listener = nil
			return nil, ctx.Err()
		case a := <-ch:
			if a.err != nil {
				logx.CloseQuiet(ln)
				o.Listener = nil
				if xio.IsTimeoutErr(a.err) {
					if g != nil && g.Log != nil {
						g.Log.Warningf("accept: Connection timed out")
					}
					return nil, xio.ErrAcceptTimeout
				}
				return nil, a.err
			}
			if err := filter(a.c); err != nil {
				if g != nil && g.Log != nil {
					g.Log.Noticef("%s", err)
				}
				xio.CloseRefusedPeer(a.c)
				continue
			}
			conn = a.c
		}
		break
	}
	logx.CloseQuiet(ln)
	o.Listener = nil
	if g != nil && g.Log != nil {
		g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	}
	xio.RememberAddrs(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	o.Stream = st
	return o, nil
}

func sctpNetwork(tcpNet string) string {
	switch tcpNet {
	case "tcp6":
		return "sctp6"
	case "tcp":
		return "sctp"
	default:
		return "sctp4"
	}
}

func tcpNetwork(sctpNet string) string {
	switch sctpNet {
	case "sctp6":
		return "tcp6"
	case "sctp":
		return "tcp"
	default:
		return "tcp4"
	}
}
