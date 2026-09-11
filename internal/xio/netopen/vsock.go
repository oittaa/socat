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
	if !s.Network.VSOCKConnectSet {
		return nil, fmt.Errorf("%s: requires <cid>:<port>", s.Type)
	}
	remote := vsockEndpoint{cid: s.Network.VSOCKConnect.CID, port: s.Network.VSOCKConnect.Port}
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
	if !s.Network.VSOCKListenSet {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Network.VSOCKListen
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

func parseVsockBindOption(s addrconfig.Address, portAllowed bool) (ep vsockEndpoint, set bool, err error) {
	if !s.Network.VSOCKBindSet {
		return vsockEndpoint{}, false, nil
	}
	if s.Network.VSOCKBindHasPort && !portAllowed {
		return vsockEndpoint{}, true, fmt.Errorf("port specification not allowed in this bind option")
	}
	return vsockEndpoint{cid: s.Network.VSOCKBind.CID, port: s.Network.VSOCKBind.Port}, true, nil
}

type vsockSocketArgs struct {
	family   int
	socktype int
	protocol int
}

func parseVsockSocketArgs(s addrconfig.Address) (vsockSocketArgs, error) {
	args := vsockSocketArgs{
		family:   vsockDefaultFamily,
		socktype: syscall.SOCK_STREAM,
		protocol: 0,
	}
	if s.Network.ProtocolSet {
		args.family = s.Network.ProtocolFamily
	}
	if s.Network.SocketType.Set {
		args.socktype = s.Network.SocketType.Value
	}
	if s.Network.SocketProtocol.Set {
		args.protocol = s.Network.SocketProtocol.Value
	}
	return args, nil
}
