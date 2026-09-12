package netopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/relay"
)

func openUnixListen(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if s.Network.SocketPath == "" {
		// Fail fast: testaddrs uses UNIX-LISTEN::::: probes.
		return nil, fmt.Errorf("UNIX-LISTEN requires path")
	}
	path := s.Network.SocketPath
	if s.Network.BindSet {
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
	doUnlink := unixUnlinkOnClose(s)
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(doUnlink)
	}

	// mode/perm/user then perm-early/user-early/group-early on the socket
	// file after bind.
	if err := xio.ApplyConfiguredNamedAfterBind(path, s, nil); err != nil {
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
			return xio.SetupAccepted(s, c, xio.FDSkipOwner)
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
func openAbstractListen(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if s.Network.SocketPath == "" {
		return nil, fmt.Errorf("ABSTRACT-LISTEN requires name")
	}
	name := s.Network.SocketPath
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
			return xio.SetupAccepted(s, c, xio.FDSkipOwner)
		},
		CloseListener: func() error { return ln.Close() },
		AfterAccept: func(g *xio.Global, conn net.Conn) error {
			rememberUnixListenAddrs(g, path, conn)
			return nil
		},
	})
}

func applyAbstractListenerFDPhase(ln net.Listener, s addrconfig.Address) error {
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
		g.Peer.SockAddr = path
		g.Peer.SockPort = ""
		g.Peer.PeerPort = ""
		if ra := conn.RemoteAddr(); ra != nil {
			if ua, ok := ra.(*net.UnixAddr); ok && ua.Name != "" {
				g.Peer.PeerAddr = ua.Name
				return
			}
			if s := ra.String(); s != "" {
				g.Peer.PeerAddr = s
				return
			}
		}
		g.Peer.PeerAddr = path
		return
	}
	if g.Peer.PeerAddr == "" {
		if ra := conn.RemoteAddr(); ra != nil {
			if s := ra.String(); s != "" {
				g.Peer.PeerAddr = s
				return
			}
		}
		g.Peer.PeerAddr = path
	}
}
