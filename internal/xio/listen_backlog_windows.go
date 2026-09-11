//go:build windows

package xio

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
)

// RejectUnsupportedListenBacklog rejects a backlog that Winsock cannot apply
// through Go's listener API.
func RejectUnsupportedListenBacklog(s addrconfig.Address) error {
	config := s
	if config.Network.Backlog.Set {
		return fmt.Errorf("backlog: not supported on Windows")
	}
	return nil
}

// ListenStream uses the provider-selected Windows backlog. Go always
// listens with SOMAXCONN (golang/go#39000), and Winsock ignores a later
// backlog change on an already-listening overlapped socket.
func ListenStream(ctx context.Context, lc net.ListenConfig, network, address string, s addrconfig.Address) (net.Listener, error) {
	if err := RejectUnsupportedListenBacklog(s); err != nil {
		return nil, err
	}
	return lc.Listen(ctx, network, address)
}
