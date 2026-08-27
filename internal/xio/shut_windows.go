//go:build windows

package xio

import "github.com/oittaa/socat/internal/relay"

func shutdownWritePolicy(stream relay.Stream) error {
	// Windows ShutdownWrite(fd) is a no-op (IOCP). TCP CloseWrite on the
	// inner net.Conn is the socket-style half-close.
	return stream.ShutdownWrite()
}
