package netopen

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUnixListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		// Fail fast: testaddrs uses UNIX-LISTEN::::: probes.
		return nil, fmt.Errorf("UNIX-LISTEN requires path")
	}
	path := s.Params[0]
	if s.HasOption("bind") {
		// bind= on UNIX-LISTEN is invalid (must not bind twice).
		return nil, fmt.Errorf("option \"bind\" with UNIX-LISTEN is not supported")
	}
	network, _, err := unixSocketNetwork(s)
	if err != nil {
		return nil, err
	}
	if network == "unixgram" {
		return nil, fmt.Errorf("%s: SOCK_DGRAM does not support listen; use UNIX-RECV or UNIX-RECVFROM", s.Type)
	}

	if err := prepareUnixFilesystemPath(path, s); err != nil {
		return nil, err
	}

	ln, err := listenUnixNetwork(ctx, s, network, path)
	if err != nil {
		return nil, err
	}

	// Go's UnixListener unlinks the path on Close by default. Match
	// unlink-close: default true; unlink-close=0 keeps the filesystem entry.
	doUnlink := !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(doUnlink)
	}

	// mode/perm/user then perm-early/user-early/group-early on the socket
	// file after bind.
	if err := xio.ApplyNamedAfterBind(path, s, nil); err != nil {
		_ = ln.Close()
		if !xio.IsAbstract(path) {
			_ = xio.Unlink(path)
		}
		return nil, err
	}
	if xio.IsAbstract(path) {
		if err := applyAbstractListenerFDPhase(ln, s); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}

	// Ensure path is removed on SIGTERM (SetUnlinkOnClose only runs on Close).
	unregister := func() {}
	if doUnlink && !xio.IsAbstract(path) {
		unregister = xio.RegisterUnlinkPath(path)
	}

	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    "UNIX-LISTEN:" + path,
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.SetupStream(s, relay.NetStream{Conn: c})
		},
		ListeningLog: "listening on " + path,
		CloseListener: func() error {
			unregister()
			return ln.Close()
		},
		AfterAccept: func(g *xio.Global, conn net.Conn) error {
			rememberUnixListenAddrs(g, path, conn)
			return nil
		},
	})
}

// openAbstractListen: ABSTRACT-LISTEN:name — stream listen in Linux abstract namespace.
func openAbstractListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-LISTEN requires name")
	}
	name := s.Params[0]
	if !xio.IsAbstract(name) {
		name = "@" + name
	}
	path := unixAddr(name)
	network, _, err := unixSocketNetwork(s)
	if err != nil {
		return nil, err
	}
	if network == "unixgram" {
		return nil, fmt.Errorf("%s: SOCK_DGRAM does not support listen; use ABSTRACT-RECV or ABSTRACT-RECVFROM", s.Type)
	}
	ln, err := listenUnixNetwork(ctx, s, network, path)
	if err != nil {
		return nil, err
	}
	if err := applyAbstractListenerFDPhase(ln, s); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    "ABSTRACT-LISTEN:" + name,
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.SetupStream(s, relay.NetStream{Conn: c})
		},
		CloseListener: func() error { return ln.Close() },
		AfterAccept: func(g *xio.Global, conn net.Conn) error {
			rememberUnixListenAddrs(g, path, conn)
			return nil
		},
	})
}

func applyAbstractListenerFDPhase(ln net.Listener, s parse.Spec) error {
	sc, ok := ln.(syscall.Conn)
	if !ok {
		return fmt.Errorf("%s: listener does not expose a descriptor", s.Type)
	}
	return xio.ApplyFDPhaseLifecycleToConn(sc, s)
}

// rememberUnixListenAddrs restores filesystem UNIX-LISTEN environment
// fields after OpenListenSession's RememberAddrs. Unnamed peers fall back to
// the listen path. Abstract sockets keep LocalAddr/RemoteAddr from RememberAddrs
// except when the peer address is empty.
func rememberUnixListenAddrs(g *xio.Global, path string, conn net.Conn) {
	if g == nil {
		return
	}
	if !xio.IsAbstract(path) {
		g.SockAddr = path
		g.SockPort = ""
		g.PeerPort = ""
		if ra := conn.RemoteAddr(); ra != nil {
			if ua, ok := ra.(*net.UnixAddr); ok && ua.Name != "" {
				g.PeerAddr = ua.Name
				return
			}
			if s := ra.String(); s != "" {
				g.PeerAddr = s
				return
			}
		}
		g.PeerAddr = path
		return
	}
	if g.PeerAddr == "" {
		if ra := conn.RemoteAddr(); ra != nil {
			if s := ra.String(); s != "" {
				g.PeerAddr = s
				return
			}
		}
		g.PeerAddr = path
	}
}
