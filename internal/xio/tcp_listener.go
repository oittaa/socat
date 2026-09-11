package xio

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/oittaa/socat/internal/addrconfig"
)

// TCPListenAddress resolves the bind address without creating a socket.
func TCPListenAddress(ctx context.Context, s addrconfig.Address, network string, port addrconfig.PortTarget) (string, error) {
	host, err := ListenBindHost(s, network)
	if err != nil {
		return "", err
	}
	ip, err := ResolveIPTarget(ctx, s, network, host)
	if err != nil {
		return "", err
	}
	n, err := ResolvePort(network, port)
	if err != nil {
		return "", err
	}
	formatted := host.String()
	if ip != nil {
		formatted = FormatIPForNetwork(network, ip)
	}
	if formatted == "" {
		return "", fmt.Errorf("%s: bind requires a host", s.Type)
	}
	return net.JoinHostPort(formatted, strconv.Itoa(n)), nil
}

// ListenTCP binds a prepared address with the requested socket options.
func ListenTCP(ctx context.Context, s addrconfig.Address, network, addr string) (net.Listener, error) {
	return ListenStream(ctx, NewTCPListenConfig(s), network, addr, s)
}
