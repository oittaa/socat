package netopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/xio"
)

// VSOCK-CONNECT / VSOCK-LISTEN (Linux AF_VSOCK stream).
//
// Go's net.FileConn / net.FileListener reject AF_VSOCK (golang/go#69769), so
// we drive unix.Socket + a small net.Conn/net.Listener on golang.org/x/sys/unix
// instead of importing github.com/mdlayher/vsock (which would pull
// github.com/mdlayher/socket). Listen binds VMADDR_CID_ANY; mdlayher
// Listen() uses the local CID from ioctl — bind ANY instead.
//
// Listen port 0 is passed through to bind(2). Linux rejects vsock port 0
// with EACCES. Do not map 0 to VMADDR_PORT_ANY.
// Ephemeral listen is VSOCK-LISTEN:-1 (uint32 0xffffffff).

const (
	vsockCIDAny  = 0xffffffff
	vsockPortAny = 0xffffffff
	// vsockDefaultFamily is Linux AF_VSOCK (40). vsock.go is compiled on
	// every GOOS; unix.AF_VSOCK is Linux-only.
	vsockDefaultFamily = 40
)

func openVSOCKConnect(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	remote, err := parseVsockConnectParams(s)
	if err != nil {
		return nil, err
	}
	timeout := xio.ConnectTimeout(s)

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, g, "vsock connect", func() error {
			c, e := dialVSOCK(dialRequest{ctx: dctx, config: s, g: g, timeout: timeout}, remote)
			if e != nil {
				return e
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

func openVSOCKListen(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
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

func parseVsockConnectParams(s addrconfig.Address) (vsockEndpoint, error) {
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

func parseVsockListenPort(s addrconfig.Address) (uint32, error) {
	if len(s.Params) != 1 || s.Params[0] == "" {
		return 0, fmt.Errorf("%s requires port", s.Type)
	}
	port, err := parseVsockU32(s.Params[0])
	if err != nil {
		return 0, fmt.Errorf("%s: port: %w", s.Type, err)
	}
	return port, nil
}

// parseVsockBindOption parses bind= [cid][:(port)].
// Listen rejects a colon (CID only). Connect allows cid:port.
func parseVsockBindOption(s addrconfig.Address, portAllowed bool) (ep vsockEndpoint, set bool, err error) {
	config := s
	vsock := config.Network.VSOCK
	if !vsock.BindSet {
		return vsockEndpoint{}, false, nil
	}
	if vsock.BindHasPort && !portAllowed {
		return vsockEndpoint{}, true, fmt.Errorf("port specification not allowed in this bind option")
	}
	return vsockEndpoint{cid: vsock.Bind.CID, port: vsock.Bind.Port}, true, nil
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

// parseVsockSocketArgs reads pf=, socktype, and so-protocol/protocol before socket().
func parseVsockSocketArgs(s addrconfig.Address) (vsockSocketArgs, error) {
	args := vsockSocketArgs{
		family:   vsockDefaultFamily,
		socktype: syscall.SOCK_STREAM,
		protocol: 0,
	}
	config := s
	if config.Network.ProtocolSet {
		args.family = config.Network.ProtocolFamily
	}
	if config.Network.SocketType.Set {
		args.socktype = config.Network.SocketType.Value
	}
	if config.Network.SocketProtocol.Set {
		args.protocol = config.Network.SocketProtocol.Value
	}
	return args, nil
}

// parseVsockU32: ParseSizeT stored in uint32 (so -1 becomes VMADDR_*_ANY).
func parseVsockU32(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}
	n, err := xio.ParseSizeT(s)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil // #nosec G115 -- ParseSizeT truncates to uint32 (so -1 is 0xffffffff)
}
