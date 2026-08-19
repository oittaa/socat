package netopen

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUnixListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		// Fail fast: classic testaddrs uses UNIX-LISTEN::::: probes.
		return nil, fmt.Errorf("UNIX-LISTEN requires path")
	}
	path := s.Params[0]
	if s.HasOption("bind") {
		// Classic: bind= on UNIX-LISTEN is invalid (must not bind twice).
		return nil, fmt.Errorf("option \"bind\" with UNIX-LISTEN is not supported")
	}
	network, _, err := unixSocketNetwork(s)
	if err != nil {
		return nil, err
	}
	if network == "unixgram" {
		return nil, fmt.Errorf("%s: SOCK_DGRAM does not support listen; use UNIX-RECV or UNIX-RECVFROM", s.Type)
	}

	if s.BoolOption("unlink-early") {
		_ = os.Remove(path)
	} else if _, err := os.Stat(path); err == nil {
		// classic may fail if exists; try remove if reuseaddr
		if s.BoolOption("reuseaddr") {
			_ = os.Remove(path)
		}
	}

	lc := net.ListenConfig{}
	var ln net.Listener
	err = xio.WithUmask(s, func() error {
		var e error
		ln, e = lc.Listen(ctx, network, path)
		return e
	})
	if err != nil {
		return nil, err
	}

	// Go's UnixListener unlinks the path on Close by default. Match classic
	// unlink-close: default true; unlink-close=0 keeps the filesystem entry.
	doUnlink := !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(doUnlink)
	}

	// mode/perm/user on socket file (classic fchmod/fchown after bind)
	if err := xio.ApplyPerm(path, s, nil); err != nil {
		// Non-fatal for some platforms; still try mode=
		if mode := xio.ParseFileMode(s, 0); mode != 0 {
			_ = os.Chmod(path, mode)
		}
	}
	_ = xio.ApplyOwner(path, s, nil)

	// Ensure path is removed on SIGTERM (SetUnlinkOnClose only runs on Close).
	unregister := func() {}
	if doUnlink && !xio.IsAbstract(path) {
		unregister = xio.RegisterUnlinkPath(path)
	}

	fork := s.BoolOption("fork")
	o := &xio.Opened{
		Kind:     xio.ListenKind(fork),
		Listener: ln,
		Label:    "UNIX-LISTEN:" + path,
	}
	o.AddCleanup(func() {
		unregister()
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
	})

	if fork {
		go func() {
			<-ctx.Done()
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
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
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		o.Listener = nil
		return nil, ctx.Err()
	case a := <-ch:
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		o.Listener = nil
		if a.err != nil {
			_ = o.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
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
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		_ = o.Close()    // #nosec G104 -- Close on cleanup; the first error is already returned
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
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, network, path)
	if err != nil {
		return nil, err
	}
	fork := s.BoolOption("fork")
	o := &xio.Opened{
		Kind:     xio.ListenKind(fork),
		Listener: ln,
		Label:    "ABSTRACT-LISTEN:" + name,
	}
	o.AddCleanup(func() { _ = ln.Close() }) // #nosec G104 -- Close on cleanup; the first error is already returned
	if fork {
		go func() {
			<-ctx.Done()
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		}()
		return o, nil
	}
	// Non-fork: accept one; honour accept-timeout (classic ABSTRACT_USER etc.).
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
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, ctx.Err()
	case a := <-ch:
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
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
			_ = a.c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, err
		}
		o.Stream = st
		return o, nil
	}
}
