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

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

const unixTempChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// resolveUnixBind returns bind= or a unique unix-bind-tempname path.
func resolveUnixBind(s parse.Spec) (string, error) {
	config, err := xio.OpeningConfig(context.Background(), s)
	if err != nil {
		return "", err
	}
	return resolveUnixBindConfig(config)
}

func resolveUnixBindConfig(config addrconfig.Address) (string, error) {
	hasTemp := config.Network.UnixBindTempname.Set
	hasBind := config.Network.BindSet || config.Common.ConnectBind.Set
	if hasTemp && hasBind {
		return "", fmt.Errorf("do not use both options bind and unix-bind-tempname")
	}
	if !hasTemp {
		return xio.BindHost(config), nil
	}
	pat := config.Network.UnixBindTempname.Value
	if pat == "" || pat == "1" {
		pat = ""
	}
	return unixTempnam(pat)
}

// unixTempnam fills XXXXXX like tempnam(3).
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

func openUnixConnect(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
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
	req := dialRequest{ctx: ctx, spec: s, g: g, timeout: xio.ConnectTimeout(ctx, s)}
	if network == "unixgram" {
		return openUnixDgramClient(req, path, bindPath, true)
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
		req.network = candidate
		conn, err = dialUnixNetwork(req, path, bindPath)
		if err == nil {
			break
		}
		if !autodetect || !unixTypeMismatch(err, bindPath != "") {
			return nil, err
		}
	}
	if err != nil {
		// Generic UNIX/UNIX-CLIENT/GOPEN probes stream, seqpacket, then dgram.
		return openUnixDgramClient(req, path, bindPath, false)
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
	config, err := xio.OpeningConfig(ctx, s)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	// Filesystem (non-ABSTRACT) clients default unlink-close=1 after a
	// successful bind. Same helper as datagram; ABSTRACT / unlink-close=0 skip
	// the unlink.
	life := trackUnixBind(bindPath, config)
	if err := xio.ApplyConfiguredNamedAfterBind(bindPath, config, nil); err != nil {
		life.drop(conn)
		return nil, err
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.SetupStream(s, st)
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

func dialUnixNetwork(req dialRequest, path, bindPath string) (net.Conn, error) {
	return dialUnixSocklen(req, path, bindPath)
}

// prepareUnixClientBind runs before a client bind=. unlink-early removes the
// name; otherwise an existing entry is left for bind(2) to fail with EADDRINUSE.
func prepareUnixClientBind(path string, config addrconfig.Address) error {
	if path == "" || xio.IsAbstract(path) {
		return nil
	}
	if !config.File.UnlinkEarly.Value {
		return nil
	}
	if err := xio.Unlink(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unlink %s: %w", path, err)
	}
	return nil
}

// unixBindCreated is the directory entry created by a successful client bind.
type unixBindCreated struct {
	path string
	info os.FileInfo
}

func rememberUnixBindCreated(path string) unixBindCreated {
	if path == "" || xio.IsAbstract(path) {
		return unixBindCreated{}
	}
	info, err := os.Lstat(path)
	if err != nil || !xio.SnapshotFileIdentity(info) {
		return unixBindCreated{}
	}
	return unixBindCreated{path: path, info: info}
}

func (c unixBindCreated) unlink() {
	if c.path == "" || c.info == nil {
		return
	}
	current, err := os.Lstat(c.path)
	if err != nil || !os.SameFile(c.info, current) {
		return
	}
	_ = xio.Unlink(c.path)
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
// emptyIsEOF is set for an explicit datagram socktype, which is used as a
// stream: a zero-length packet ends the transfer. Autodetect fallback to
// datagram still ignores empty packets unless null-eof is set.
func openUnixDgramClient(req dialRequest, path, bindPath string, emptyIsEOF bool) (*xio.Opened, error) {
	req.network = "unixgram"
	conn, err := dialUnixNetwork(req, path, bindPath)
	if err != nil {
		return nil, err
	}
	config, err := xio.OpeningConfig(req.ctx, req.spec)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	life := trackUnixBind(bindPath, config)
	if err := xio.ApplyConfiguredNamedAfterBind(bindPath, config, nil); err != nil {
		life.drop(conn)
		return nil, err
	}
	if req.g != nil && req.g.Log != nil {
		req.g.Log.Infof("successfully connected to %s", path)
	}
	if req.g != nil {
		if bindPath != "" {
			req.g.SockAddr = bindPath
		} else {
			req.g.SockAddr = path
		}
		req.g.PeerAddr = path
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		if err := applyUnixgramSocketOptions(uc, req.spec); err != nil {
			life.drop(conn)
			return nil, err
		}
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	if emptyIsEOF {
		st = xio.WrapMessageEOF(st)
	}
	st, err = xio.WrapOpened(req.spec, st)
	if err != nil {
		life.drop(conn)
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "UNIX:" + path}
	life.attach(o)
	return o, nil
}

// abstract unix (Linux): ABSTRACT-* and @path / \0path forms.
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

// abstractName maps ABSTRACT-*:path (even if path is a filesystem path
// that was touch'ed so non-abstract would fail) to the abstract namespace name.
func abstractName(raw string) string {
	if xio.IsAbstract(raw) {
		return unixAddr(raw)
	}
	// ABSTRACT-RECVFROM:/tmp/foo uses abstract name equal to the string
	// (with leading NUL), not a filesystem socket.
	return "\x00" + raw
}
