//go:build linux || darwin

package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
)

// DefaultListenBacklog is the Linux/macOS listen queue length when backlog=
// is omitted.
const DefaultListenBacklog = 5

// ListenBacklog returns the requested Linux/macOS stream backlog.
func ListenBacklog(s parse.Spec) (int, error) {
	v := s.OptionValue("backlog", "")
	if v == "" {
		return DefaultListenBacklog, nil
	}
	n, err := ParseIntAny(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("backlog: invalid value %q", v)
	}
	return n, nil
}

// RejectUnsupportedListenBacklog is a no-op where the requested backlog can
// be applied.
func RejectUnsupportedListenBacklog(parse.Spec) error { return nil }

// ListenStream creates a stream listener and applies its configured backlog.
func ListenStream(ctx context.Context, lc net.ListenConfig, network, address string, s parse.Spec) (net.Listener, error) {
	ln, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	backlog, err := ListenBacklog(s)
	if err == nil {
		err = ApplyListenBacklog(ln, backlog)
	}
	if err != nil {
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
