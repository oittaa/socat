//go:build linux || darwin

package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
)

// DefaultListenBacklog is the Linux/macOS listen queue length when backlog=
// is omitted.
const DefaultListenBacklog = 5

// ListenBacklog returns the requested Linux/macOS stream backlog.
func ListenBacklog(s addrconfig.Address) (int, error) {
	return configuredListenBacklog(s), nil
}

func configuredListenBacklog(config addrconfig.Address) int {
	if config.Network.Backlog.Set {
		return config.Network.Backlog.Value
	}
	return DefaultListenBacklog
}

// RejectUnsupportedListenBacklog is a no-op where the requested backlog can
// be applied.
func RejectUnsupportedListenBacklog(addrconfig.Address) error { return nil }

func RejectUnsupportedUnixTightSocklen(addrconfig.Address) error { return nil }

// ListenStream creates a stream listener and applies its configured backlog.
// Go's net.Listen uses SOMAXCONN; ApplyListenBacklog issues a second listen(2).
func ListenStream(ctx context.Context, lc net.ListenConfig, network, address string, s addrconfig.Address) (net.Listener, error) {
	backlog, err := ListenBacklog(s)
	if err != nil {
		return nil, err
	}
	ln, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err := ApplyListenBacklog(ln, backlog); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("backlog: %w", err)
	}
	return ln, nil
}

// ApplyListenBacklog updates an existing Linux/macOS listen queue.
func ApplyListenBacklog(ln net.Listener, backlog int) error {
	sc, ok := ln.(syscall.Conn)
	if !ok {
		return fmt.Errorf("listener does not expose its socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = setListenBacklog(int(fd), backlog)
	})
	return errors.Join(controlErr, optionErr)
}
