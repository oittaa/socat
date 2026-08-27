//go:build !linux

package netopen

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func listenIPDgram(context.Context, string, *net.UDPAddr, parse.Spec, int) (*net.UDPConn, error) {
	return nil, fmt.Errorf("UDP-Lite is only implemented on Linux")
}

func dialIPDgram(context.Context, string, *net.UDPAddr, *net.UDPAddr, parse.Spec, int, func(string, string, syscall.RawConn) error, time.Duration) (*net.UDPConn, error) {
	return nil, fmt.Errorf("UDP-Lite is only implemented on Linux")
}
