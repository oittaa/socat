package netopen

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// Classic VSOCK-CONNECT / VSOCK-LISTEN (Linux AF_VSOCK stream).
//
// Baseline: official socat tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same tree (xio-vsock.c,
// sockaddr_vm_parse, and the man page are identical).
//
// Go's net.FileConn / net.FileListener reject AF_VSOCK (golang/go#69769), so
// we drive unix.Socket + a small net.Conn/net.Listener on golang.org/x/sys/unix
// instead of importing github.com/mdlayher/vsock (which would pull
// github.com/mdlayher/socket). Classic listen binds VMADDR_CID_ANY; mdlayher
// Listen() uses the local CID from ioctl — we match classic.
//
// Listen port 0 is passed through to bind(2). Linux rejects vsock port 0
// with EACCES (classic: "Permission denied"). Do not map 0 to
// VMADDR_PORT_ANY; that is a non-security classic divergence.
// Ephemeral listen is classic VSOCK-LISTEN:-1 (uint32 0xffffffff).

const (
	vsockCIDAny  = 0xffffffff
	vsockPortAny = 0xffffffff
	// vsockDefaultFamily is Linux AF_VSOCK (40). vsock.go is compiled on
	// every GOOS; unix.AF_VSOCK is Linux-only.
	vsockDefaultFamily = 40
)

func openVSOCKConnect(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	remote, err := parseVsockConnectParams(s)
	if err != nil {
		return nil, err
	}
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
		err := xio.WithRetry(dctx, s, g, "vsock connect", func() error {
			setSockErr = nil
			c, e := dialVSOCK(dctx, remote, s, g, timeout, control)
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
		Label: fmt.Sprintf("vsock:%s", remote),
		Dial:  dialOnce,
		LogOK: true,
	})
}

func openVSOCKListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	port, err := parseVsockListenPort(s)
	if err != nil {
		return nil, err
	}
	ln, err := listenVSOCK(ctx, port, s, g)
	if err != nil {
		return nil, err
	}
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    fmt.Sprintf("vsock-LISTEN:%d", port),
	})
}

type vsockEndpoint struct {
	cid  uint32
	port uint32
}

func (e vsockEndpoint) String() string {
	return fmt.Sprintf("%d:%d", e.cid, e.port)
}

func parseVsockConnectParams(s parse.Spec) (vsockEndpoint, error) {
	if len(s.Params) != 2 {
		return vsockEndpoint{}, fmt.Errorf("%s: requires <cid>:<port>", s.Type)
	}
	cid, err := parseVsockCID(s.Params[0])
	if err != nil {
		return vsockEndpoint{}, fmt.Errorf("%s: cid: %w", s.Type, err)
	}
	port, err := parseVsockU32(s.Params[1])
	if err != nil {
		return vsockEndpoint{}, fmt.Errorf("%s: port: %w", s.Type, err)
	}
	return vsockEndpoint{cid: cid, port: port}, nil
}

func parseVsockListenPort(s parse.Spec) (uint32, error) {
	if len(s.Params) != 1 || s.Params[0] == "" {
		return 0, fmt.Errorf("%s requires port", s.Type)
	}
	port, err := parseVsockU32(s.Params[0])
	if err != nil {
		return 0, fmt.Errorf("%s: port: %w", s.Type, err)
	}
	return port, nil
}

// parseVsockBindOption parses classic bind= [cid][:(port)].
// Listen passes portAllowed=false (retropt_bind feats=1): a colon is rejected
// and only the CID is applied. Connect passes portAllowed=true (feats=3).
func parseVsockBindOption(s parse.Spec, portAllowed bool) (ep vsockEndpoint, set bool, err error) {
	raw, ok := s.OptionNamed("bind")
	if !ok {
		return vsockEndpoint{}, false, nil
	}
	bind := raw.Value
	cidStr, portStr, hasPort := splitVsockBind(bind)
	if hasPort && !portAllowed {
		return vsockEndpoint{}, true, fmt.Errorf("port specification not allowed in this bind option")
	}
	cid, err := parseVsockCID(cidStr)
	if err != nil {
		return vsockEndpoint{}, true, fmt.Errorf("bind: cid: %w", err)
	}
	ep.cid = cid
	if hasPort {
		port, err := parseVsockU32(portStr)
		if err != nil {
			return vsockEndpoint{}, true, fmt.Errorf("bind: port: %w", err)
		}
		ep.port = port
	} else {
		ep.port = vsockPortAny
	}
	return ep, true, nil
}

func splitVsockBind(bind string) (cidStr, portStr string, hasPort bool) {
	if i := strings.IndexByte(bind, ':'); i >= 0 {
		return bind[:i], bind[i+1:], true
	}
	return bind, "", false
}

func parseVsockCID(s string) (uint32, error) {
	if s == "" {
		return vsockCIDAny, nil
	}
	return parseVsockU32(s)
}

type vsockSocketArgs struct {
	family   int
	socktype int
	protocol int
}

// parseVsockSocketArgs matches classic xioopen_vsock_* : retropt_socket_pf,
// OPT_SO_TYPE, OPT_SO_PROTOTYPE before socket().
func parseVsockSocketArgs(s parse.Spec) (vsockSocketArgs, error) {
	args := vsockSocketArgs{
		family:   vsockDefaultFamily,
		socktype: syscall.SOCK_STREAM,
		protocol: 0,
	}
	if v := s.OptionValue("pf", ""); v != "" {
		pf, err := parseClassicSocketPF(v)
		if err != nil {
			return vsockSocketArgs{}, err
		}
		args.family = pf
	}
	if o, ok := s.OptionNamed("socktype"); ok {
		n, err := parseVsockSocketInt(o, "socktype")
		if err != nil {
			return vsockSocketArgs{}, err
		}
		args.socktype = n
	}
	proto, err := parseVsockProtocolOption(s)
	if err != nil {
		return vsockSocketArgs{}, err
	}
	args.protocol = proto
	return args, nil
}

// parseClassicSocketPF matches retropt_socket_pf in xio-socket.c (tag-1.8.1.3):
// a leading digit is strtoul base 0; inet/inet4/ip4/ipv4 → PF_INET;
// inet6/ip6/ipv6 → PF_INET6; anything else is an error.
func parseClassicSocketPF(name string) (int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return vsockDefaultFamily, nil
	}
	if name[0] >= '0' && name[0] <= '9' {
		n, err := xio.ParseIntAny(name)
		if err != nil {
			return 0, fmt.Errorf("unknown protocol family %q", name)
		}
		return n, nil
	}
	switch strings.ToLower(name) {
	case "inet", "inet4", "ip4", "ipv4":
		return syscall.AF_INET, nil
	case "inet6", "ip6", "ipv6":
		return syscall.AF_INET6, nil
	default:
		return 0, fmt.Errorf("unknown protocol family %q", name)
	}
}

func parseVsockProtocolOption(s parse.Spec) (int, error) {
	if o, ok := s.OptionNamed("so-protocol"); ok {
		return parseVsockSocketInt(o, "so-protocol")
	}
	// Classic alias "protocol" is also the Go WebSocket subprotocol option, so
	// it is not canonicalized to so-protocol and is not read here.
	return 0, nil
}

func parseVsockSocketInt(o parse.Option, name string) (int, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, fmt.Errorf("option %q requires a number", name)
	}
	n, err := xio.ParseIntAny(o.Value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q", name, o.Value)
	}
	return n, nil
}

// parseVsockU32 matches classic sockaddr_vm_parse: strtoul(..., 0) stored in
// uint32 (so -1 becomes VMADDR_*_ANY).
func parseVsockU32(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	n, err := xio.ParseSizeT(s)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil // #nosec G115 -- classic strtoul assigned to uint32
}
