package netopen

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

const unixTempChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// resolveUnixBind returns bind= or a unique unix-bind-tempname path (classic).
func resolveUnixBind(s parse.Spec) (string, error) {
	hasTemp := s.HasOption("unix-bind-tempname")
	hasBind := s.HasOption("bind")
	if hasTemp && hasBind {
		return "", fmt.Errorf("do not use both options bind and unix-bind-tempname")
	}
	if !hasTemp {
		return s.OptionValue("bind", ""), nil
	}
	o, _ := s.OptionNamed("unix-bind-tempname")
	pat := ""
	if o.Has && o.Value != "" && o.Value != "1" {
		pat = o.Value
	}
	return unixTempnam(pat)
}

// unixTempnam fills XXXXXX like classic xio_tempnam / tempnam(3).
func unixTempnam(pattern string) (string, error) {
	if pattern == "" {
		pattern = "/tmp/socat-bind.XXXXXX"
	}
	idx := strings.LastIndex(pattern, "XXXXXX")
	if idx < 0 {
		return "", fmt.Errorf("unix-bind-tempname: path pattern is not valid")
	}
	abs := xio.IsAbstract(unixAddr(pattern))
	var b [6]byte
	for n := 0; n < 10000; n++ {
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		var out [6]byte
		for i := 0; i < 6; i++ {
			out[i] = unixTempChars[int(b[i])%len(unixTempChars)]
		}
		name := pattern[:idx] + string(out[:]) + pattern[idx+6:]
		if abs {
			return name, nil
		}
		if _, err := os.Lstat(unixAddr(name)); os.IsNotExist(err) {
			return name, nil
		}
	}
	return "", fmt.Errorf("unix-bind-tempname: no free name")
}

func openUnixConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UNIX-CONNECT requires path")
	}
	path := unixAddr(s.Params[0])
	bindPath, err := resolveUnixBind(s)
	if err != nil {
		return nil, err
	}
	if bindPath != "" {
		if strings.HasPrefix(strings.ToUpper(s.Type), "ABSTRACT") {
			bindPath = abstractName(bindPath)
		} else {
			bindPath = unixAddr(bindPath)
		}
	}

	// Explicit socktype=2 (SOCK_DGRAM) or classic client fallback when peer is dgram.
	wantDgram := false
	if v := s.OptionValue("socktype", ""); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n == syscall.SOCK_DGRAM {
			wantDgram = true
		}
	}

	if wantDgram {
		return openUnixDgramClient(ctx, s, mode, g, path, bindPath)
	}

	var conn net.Conn
	// If stream dial with LocalAddr fails (e.g. peer is SOCK_DGRAM), the kernel
	// may have already bound the local path — remove it before dgram fallback
	// (UNIXTODGRAM: classic probes stream then dgram with the same bind= path).
	cleanupStreamBind := func() {
		if bindPath != "" && !xio.IsAbstract(bindPath) {
			_ = os.Remove(bindPath)
		}
	}
	err = xio.WithRetry(ctx, s, g, "UNIX-CONNECT", func() error {
		d := net.Dialer{}
		if bindPath != "" {
			// Classic client bind path: remove stale leftover before bind.
			if !xio.IsAbstract(bindPath) {
				_ = os.Remove(bindPath)
			}
			d.LocalAddr = &net.UnixAddr{Name: bindPath, Net: "unix"}
		}
		c, e := d.DialContext(ctx, "unix", path)
		if e != nil {
			if unixTryDgram(e, bindPath != "") {
				cleanupStreamBind()
			}
			return e
		}
		conn = c
		return nil
	})
	if unixTryDgram(err, bindPath != "") {
		cleanupStreamBind()
		return openUnixDgramClient(ctx, s, mode, g, path, bindPath)
	}
	if err != nil {
		return nil, err
	}
	if g != nil && g.Log != nil {
		g.Log.Infof("successfully connected to %s", path)
	}
	if g != nil {
		if bindPath != "" {
			g.SockAddr = bindPath
		} else {
			g.SockAddr = path
		}
		g.PeerAddr = path
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		if bindPath != "" {
			_ = os.Remove(bindPath)
		}
		return nil, err
	}
	o := &xio.Opened{
		Stream: st,
		Label:  "UNIX:" + path,
	}
	// unlink-close: remove the *local bind* path (classic client option).
	if s.BoolOption("unlink-close") && bindPath != "" {
		o.AddCleanup(func() { _ = os.Remove(bindPath) })
	}
	return o, nil
}

func unixTryDgram(err error, haveBind bool) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPROTOTYPE) {
		return true
	}
	return haveBind && (errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOTSOCK))
}

// openUnixDgramClient is UNIX:/UNIX-CONNECT as datagram (peer is RECVFROM etc.).
func openUnixDgramClient(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, path, bindPath string) (*xio.Opened, error) {
	// Reuse SENDTO path with synthetic params.
	ps := s
	ps.Params = []string{path}
	if bindPath != "" {
		var opts []parse.Option
		for _, o := range s.Options {
			if o.Name == "unix-bind-tempname" {
				continue
			}
			opts = append(opts, o)
		}
		if !s.HasOption("bind") {
			opts = append(opts, parse.Option{Name: "bind", Value: bindPath, Has: true})
		}
		ps.Options = opts
	}
	return openUnixSendto(ctx, ps, mode, g)
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

// openAbstractConnect: ABSTRACT-CONNECT / ABSTRACT-CLIENT stream connect.
func openAbstractConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("ABSTRACT-CONNECT requires name")
	}
	name := s.Params[0]
	if !xio.IsAbstract(name) {
		name = "@" + name
	}
	ps := s
	ps.Params = []string{name}
	return openUnixConnect(ctx, ps, mode, g)
}

// abstractName maps classic ABSTRACT-*:path (even if path is a filesystem path
// that was touch'ed so non-abstract would fail) to the abstract namespace name.
func abstractName(raw string) string {
	if xio.IsAbstract(raw) {
		return unixAddr(raw)
	}
	// Classic: ABSTRACT-RECVFROM:/tmp/foo uses abstract name equal to the string
	// (with leading NUL), not a filesystem socket.
	return "\x00" + raw
}
