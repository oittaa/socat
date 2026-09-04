package xio

import (
	"context"
	"net"

	"github.com/oittaa/socat/internal/parse"
)

// TCPListenAddress resolves the bind address without creating a socket.
func TCPListenAddress(ctx context.Context, s parse.Spec, network, port string) (string, error) {
	host, err := ListenBindHost(s, network, s.OptionValue("bind", ""))
	if err != nil {
		return "", err
	}
	host, err = ResolveIPHost(ctx, s, network, host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(StripBrackets(host), port), nil
}

// ListenTCP binds a prepared address with the requested socket options.
func ListenTCP(ctx context.Context, s parse.Spec, network, addr string) (net.Listener, error) {
	return ListenStream(ctx, NewTCPListenConfig(s), network, addr, s)
}
