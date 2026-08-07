package addr

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUnixConnect(ctx context.Context, s parse.Spec, _ Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UNIX-CONNECT requires path")
	}
	path := unixAddr(s.Params[0])
	bindPath := s.OptionValue("bind", "")
	if bindPath != "" {
		bindPath = unixAddr(bindPath)
	}
	netw := "unix"
	if isAbstract(path) || isAbstract(bindPath) {
		netw = "unix"
	}

	var conn net.Conn
	err := withRetry(ctx, s, g, "UNIX-CONNECT", func() error {
		d := net.Dialer{}
		if bindPath != "" {
			// Classic: bind local unix socket path before connect.
			if !isAbstract(bindPath) {
				_ = os.Remove(bindPath) // stale leftover
			}
			d.LocalAddr = &net.UnixAddr{Name: bindPath, Net: netw}
		}
		c, e := d.DialContext(ctx, netw, path)
		if e != nil {
			return e
		}
		conn = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	g.Log.Infof("successfully connected to %s", path)
	if g != nil {
		if bindPath != "" {
			g.SockAddr = bindPath
		} else {
			g.SockAddr = path
		}
		g.PeerAddr = path
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		if bindPath != "" {
			_ = os.Remove(bindPath)
		}
		return nil, err
	}
	o := &Opened{
		Stream: st,
		Label:  "UNIX:" + path,
	}
	// unlink-close: remove the *local bind* path (classic client option).
	// Default for connect is 0 (keep); only unlink when explicitly true or
	// when bind path was used with unlink-close=1.
	unlinkTarget := bindPath
	if unlinkTarget == "" {
		// Without bind, classic may still honor unlink-close on the peer path
		// only when explicitly requested — tests use bind= + unlink-close=1.
		unlinkTarget = ""
	}
	if s.BoolOption("unlink-close") && unlinkTarget != "" {
		o.addCleanup(func() { _ = os.Remove(unlinkTarget) })
	} else if bindPath != "" && !s.HasOption("unlink-close") {
		// Keep bind path by default (classic unlink-close default for connect is off).
	}
	return o, nil
}

func openUnixListen(ctx context.Context, s parse.Spec, _ Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		// Fail fast: classic testaddrs uses UNIX-LISTEN::::: probes.
		return nil, fmt.Errorf("UNIX-LISTEN requires path")
	}
	path := s.Params[0]

	if s.BoolOption("unlink-early") {
		_ = os.Remove(path)
	} else if _, err := os.Stat(path); err == nil {
		// classic may fail if exists; try remove if reuseaddr
		if s.BoolOption("reuseaddr") {
			_ = os.Remove(path)
		}
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}

	// Go's UnixListener unlinks the path on Close by default. Match classic
	// unlink-close: default true; unlink-close=0 keeps the filesystem entry.
	doUnlink := !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(doUnlink)
	}

	// mode on socket file
	if mode := parseFileMode(s, 0); mode != 0 {
		_ = os.Chmod(path, mode)
	}

	fork := s.BoolOption("fork")
	o := &Opened{
		Listener: ln,
		Fork:     fork,
		Label:    "UNIX-LISTEN:" + path,
	}
	o.addCleanup(func() { ln.Close() })

	if fork {
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		return o, nil
	}

	// accept-timeout
	at := acceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	} else if v := s.OptionValue("accept-timeout", ""); v != "" {
		if f, e := strconv.ParseFloat(v, 64); e == nil && f > 0 {
			deadline = time.Now().Add(time.Duration(f * float64(time.Second)))
		}
	}
	g.Log.Noticef("listening on %s", path)
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
		ln.Close()
		o.Listener = nil
		return nil, ctx.Err()
	case a := <-ch:
		ln.Close()
		o.Listener = nil
		if a.err != nil {
			o.Close()
			if isTimeoutErr(a.err) {
				return nil, ErrAcceptTimeout
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
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		o.Close()
		return nil, err
	}
	o.Stream = st
	return o, nil
}

// abstract unix (Linux): classic ABSTRACT-* and @path / \0path forms.
// Go net uses a leading NUL byte for abstract namespace names.
func unixAddr(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '@' {
		return string(byte(0)) + path[1:]
	}
	// Already abstract (NUL-prefixed)
	if path[0] == 0 {
		return path
	}
	return path
}

func isAbstract(path string) bool {
	return len(path) > 0 && (path[0] == 0 || path[0] == '@')
}

// openAbstractSendto implements ABSTRACT-SENDTO / ABSTRACT-CLIENT bind+datagram style.
// For stream-ish echo tests, ABSTRACT-SENDTO with bind to same name loops on dgram.
func openAbstractSendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-SENDTO requires name")
	}
	// Classic ABSTRACT-SENDTO:path — abstract name from path (filesystem path becomes abstract name).
	name := s.Params[0]
	// Use abstract form: leading @ or convert path to abstract label.
	absName := name
	if !isAbstract(absName) {
		absName = "@" + name // mark; unixAddr converts
	}
	target := unixAddr(absName)
	bindOpt := s.OptionValue("bind", "")
	var laddr *net.UnixAddr
	if bindOpt != "" {
		bp := bindOpt
		if !isAbstract(bp) {
			bp = "@" + bp
		}
		laddr = &net.UnixAddr{Name: unixAddr(bp), Net: "unixgram"}
	}
	raddr := &net.UnixAddr{Name: target, Net: "unixgram"}
	c, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		// Fallback: dial unixgram
		d := net.Dialer{}
		if laddr != nil {
			d.LocalAddr = laddr
		}
		conn, e := d.DialContext(ctx, "unixgram", raddr.String())
		if e != nil {
			return nil, e
		}
		st := relay.Stream(relay.NetStream{Conn: conn})
		st, err = wrapCommon(s, st)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return &Opened{Stream: st, Label: "ABSTRACT-SENDTO:" + name}, nil
	}
	// Connected-style: write to raddr, read any
	st := &unixgramConn{UnixConn: c, raddr: raddr}
	wrapped, err := wrapCommon(s, st)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = mode
	_ = g
	return &Opened{Stream: wrapped, Label: "ABSTRACT-SENDTO:" + name}, nil
}

type unixgramConn struct {
	*net.UnixConn
	raddr *net.UnixAddr
}

func (u *unixgramConn) Write(p []byte) (int, error) {
	return u.UnixConn.WriteToUnix(p, u.raddr)
}
func (u *unixgramConn) ShutdownWrite() error { return nil }

// silence unused on non-special builds
var _ = syscall.AF_UNIX
