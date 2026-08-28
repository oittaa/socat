package netopen

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
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

	network, explicitType, err := unixSocketNetwork(s)
	if err != nil {
		return nil, err
	}
	if network == "unixgram" {
		return openUnixDgramClient(ctx, s, mode, g, path, bindPath)
	}

	networks := []string{network}
	autodetect := !explicitType && genericUnixClient(s.Type)
	if autodetect {
		if seqpacket, ok := unixSeqpacketNetwork(); ok {
			networks = append(networks, seqpacket)
		}
	}

	var conn net.Conn
	for _, candidate := range networks {
		conn, err = dialUnixNetwork(ctx, s, g, candidate, path, bindPath)
		if err == nil {
			break
		}
		if !autodetect || !unixTypeMismatch(err, bindPath != "") {
			return nil, err
		}
	}
	if err != nil {
		// Generic UNIX/UNIX-CLIENT/GOPEN probes stream, seqpacket, then dgram.
		return openUnixDgramClient(ctx, s, mode, g, path, bindPath)
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
	// Classic xioopen_unix_connect (tag-1.8.1.3
	// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a is the same): filesystem
	// (non-ABSTRACT) clients default unlink-close=1 after a successful bind.
	// Same helper as datagram; ABSTRACT / unlink-close=0 skip the unlink.
	life := trackUnixBind(bindPath, s)
	if err := xio.ApplyNamedAfterBind(bindPath, s, nil); err != nil {
		life.drop(conn)
		return nil, err
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		life.drop(conn)
		return nil, err
	}
	o := &xio.Opened{
		Stream: st,
		Label:  "UNIX:" + path,
	}
	life.attach(o)
	return o, nil
}

func unixSocketNetwork(s parse.Spec) (network string, explicit bool, err error) {
	typ, explicit, err := xio.SocketTypeOption(s, syscall.SOCK_STREAM)
	if err != nil {
		return "", explicit, err
	}
	if !explicit {
		return "unix", false, nil
	}
	switch typ {
	case syscall.SOCK_STREAM:
		return "unix", true, nil
	case syscall.SOCK_DGRAM:
		return "unixgram", true, nil
	case syscall.SOCK_SEQPACKET:
		return "unixpacket", true, nil
	default:
		return "", true, fmt.Errorf("%s: unsupported socktype=%d", s.Type, typ)
	}
}

func genericUnixClient(typ string) bool {
	switch strings.ToUpper(typ) {
	case "UNIX", "UNIX-CLIENT", "ABSTRACT-CLIENT":
		return true
	default:
		return false
	}
}

func dialUnixNetwork(ctx context.Context, s parse.Spec, g *xio.Global, network, path, bindPath string) (net.Conn, error) {
	if !unixTightSocklen(s) {
		return dialUnixUntight(ctx, s, g, network, path, bindPath)
	}
	var conn net.Conn
	err := xio.WithRetry(ctx, s, g, s.Type, func() error {
		d := net.Dialer{
			Timeout: xio.ConnectTimeout(s),
			Control: xio.DialControl(s, network, nil),
		}
		if bindPath != "" {
			// A failed protocol probe may have bound the path already.
			cleanupUnixBind(bindPath)
			d.LocalAddr = &net.UnixAddr{Name: bindPath, Net: network}
		}
		c, err := d.DialContext(ctx, network, path)
		if err != nil {
			cleanupUnixBind(bindPath)
			return err
		}
		conn = c
		return nil
	})
	return conn, err
}

func cleanupUnixBind(path string) {
	if path != "" && !xio.IsAbstract(path) {
		_ = xio.Unlink(path)
	}
}

func unixTypeMismatch(err error, haveBind bool) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPROTOTYPE) {
		return true
	}
	return haveBind && (errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOTSOCK))
}

// openUnixDgramClient is UNIX:/UNIX-CONNECT as a connected datagram socket.
// Unlike UNIX-SENDTO, it must not fall back to an unconnected socket when the
// peer has an incompatible socket type: connect(2) failure is the open error.
func openUnixDgramClient(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, path, bindPath string) (*xio.Opened, error) {
	conn, err := dialUnixNetwork(ctx, s, g, "unixgram", path, bindPath)
	if err != nil {
		return nil, err
	}
	life := trackUnixBind(bindPath, s)
	if err := xio.ApplyNamedAfterBind(bindPath, s, nil); err != nil {
		life.drop(conn)
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
	if uc, ok := conn.(*net.UnixConn); ok {
		if err := applyUnixgramSocketOptions(uc, s); err != nil {
			life.drop(conn)
			return nil, err
		}
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		life.drop(conn)
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "UNIX:" + path}
	life.attach(o)
	_ = mode
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
