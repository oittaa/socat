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
	path := s.Params[0]
	var conn net.Conn
	err := withRetry(ctx, s, g, "UNIX-CONNECT", func() error {
		var d net.Dialer
		c, e := d.DialContext(ctx, "unix", path)
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
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Opened{
		Stream: st,
		Label:  "UNIX:" + path,
	}, nil
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
		// classic may fail if exists; try remove if unlink-close semantics
		if s.BoolOption("reuseaddr") {
			_ = os.Remove(path)
		}
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
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
	if !s.HasOption("unlink-close") || s.BoolOption("unlink-close") {
		// default: remove socket on close
		if !s.BoolOption("unlink-close") {
			// classic default unlink-close=1 for unix listen
			o.addCleanup(func() { _ = os.Remove(path) })
		} else {
			o.addCleanup(func() { _ = os.Remove(path) })
		}
	}
	o.addCleanup(func() { ln.Close() })

	if fork {
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		return o, nil
	}

	// accept-timeout (also used by half-close tests indirectly via peer retry)
	if at := s.OptionValue("accept-timeout", ""); at != "" {
		if f, e := strconv.ParseFloat(at, 64); e == nil && f > 0 {
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(time.Now().Add(time.Duration(f * float64(time.Second))))
			}
		}
	}
	g.Log.Noticef("listening on %s", path)
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
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
			return nil, a.err
		}
		conn = a.c
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

// abstract unix (Linux @name) — basic support via path starting with @
func unixAddr(path string) string {
	if len(path) > 0 && path[0] == '@' {
		// Go uses \x00 prefix for abstract
		return string(byte(0)) + path[1:]
	}
	return path
}

// silence unused on non-special builds
var _ = syscall.AF_UNIX
