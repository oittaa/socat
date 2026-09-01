//go:build windows

package xio

import (
	"context"
	"fmt"
	"net"

	"github.com/oittaa/socat/internal/parse"
)

// RejectUnsupportedListenBacklog rejects a backlog that Winsock cannot apply
// through Go's listener API.
func RejectUnsupportedListenBacklog(s parse.Spec) error {
	if s.HasOption("backlog") {
		return fmt.Errorf("backlog: not supported on Windows")
	}
	return nil
}

// ListenStream uses the provider-selected Windows backlog. Winsock ignores a
// backlog change after Go has put the socket into the listening state.
func ListenStream(ctx context.Context, lc net.ListenConfig, network, address string, s parse.Spec) (net.Listener, error) {
	if err := RejectUnsupportedListenBacklog(s); err != nil {
		return nil, err
	}
	return lc.Listen(ctx, network, address)
}
