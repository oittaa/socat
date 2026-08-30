package netopen

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
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

	fork, maxChildren, ferr := xio.ForkLimits(s)
	if ferr != nil {
		unregister()
		logx.CloseQuiet(ln)
		if !xio.IsAbstract(path) {
			_ = xio.Unlink(path)
		}
		return nil, ferr
	}

	wrapConn := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}
	peerFilter := xio.NewPeerFilter(s, g)
	o := &xio.Opened{
		Kind:        xio.ListenKind(fork),
		Listener:    ln,
		Label:       "UNIX-LISTEN:" + path,
		MaxChildren: maxChildren,
		PeerFilter:  peerFilter.AllowConn,
		WrapDial:    wrapConn,
	}
	o.AcceptTimeout = xio.AcceptTimeout(s)
	o.AddCleanup(func() {
		unregister()
		logx.CloseQuiet(ln)
	})

	if fork {
		go func() {
			<-ctx.Done()
			logx.CloseQuiet(ln)
		}()
		return o, nil
	}

	// accept-timeout
	at := xio.AcceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	} else if v := s.OptionValue("accept-timeout", ""); v != "" {
		if f, e := strconv.ParseFloat(v, 64); e == nil && f > 0 {
			deadline = time.Now().Add(time.Duration(f * float64(time.Second)))
		}
	}
	if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s", path)
	}
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		if !deadline.IsZero() {
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	var conn net.Conn
	select {
	case <-ctx.Done():
		logx.CloseQuiet(ln)
		o.Listener = nil
		return nil, ctx.Err()
	case a := <-ch:
		logx.CloseQuiet(ln)
		o.Listener = nil
		if a.err != nil {
			logx.CloseQuiet(o)
			if xio.IsTimeoutErr(a.err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, a.err
		}
		conn = a.c
	}
	// UNIX env: sock = listen path; peer = client path if bound.
	if g != nil {
		g.SockAddr = path
		g.SockPort = ""
		g.PeerPort = ""
		if ra := conn.RemoteAddr(); ra != nil {
			if ua, ok := ra.(*net.UnixAddr); ok && ua.Name != "" {
				g.PeerAddr = ua.Name
			} else if s := ra.String(); s != "" {
				g.PeerAddr = s
			} else {
				g.PeerAddr = path
			}
		} else {
			g.PeerAddr = path
		}
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(conn)
		logx.CloseQuiet(o)
		return nil, err
	}
	o.Stream = st
	return o, nil
}

// openAbstractListen: ABSTRACT-LISTEN:name — stream listen in Linux abstract namespace.
func openAbstractListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
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
	fork, maxChildren, ferr := xio.ForkLimits(s)
	if ferr != nil {
		logx.CloseQuiet(ln)
		return nil, ferr
	}
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}
	peerFilter := xio.NewPeerFilter(s, g)
	o := &xio.Opened{
		Kind:        xio.ListenKind(fork),
		Listener:    ln,
		Label:       "ABSTRACT-LISTEN:" + name,
		MaxChildren: maxChildren,
		PeerFilter:  peerFilter.AllowConn,
		WrapDial:    wrapConn,
	}
	o.AcceptTimeout = xio.AcceptTimeout(s)
	o.AddCleanup(func() { logx.CloseQuiet(ln) })
	if fork {
		go func() {
			<-ctx.Done()
			logx.CloseQuiet(ln)
		}()
		return o, nil
	}
	// Non-fork: accept one; honour accept-timeout.
	at := xio.AcceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	}
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		if !deadline.IsZero() {
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	select {
	case <-ctx.Done():
		logx.CloseQuiet(ln)
		return nil, ctx.Err()
	case a := <-ch:
		logx.CloseQuiet(ln)
		o.Listener = nil
		if a.err != nil {
			if xio.IsTimeoutErr(a.err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, a.err
		}
		st := relay.Stream(relay.NetStream{Conn: a.c})
		st, err = xio.WrapCommon(s, st)
		if err != nil {
			logx.CloseQuiet(a.c)
			return nil, err
		}
		o.Stream = st
		return o, nil
	}
}

func applyAbstractListenerFDPhase(ln net.Listener, s parse.Spec) error {
	sc, ok := ln.(syscall.Conn)
	if !ok {
		return fmt.Errorf("%s: listener does not expose a descriptor", s.Type)
	}
	return xio.ApplyFDPhaseLifecycleToConn(sc, s)
}
