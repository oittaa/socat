//go:build unix

package xio

import (
	"errors"
	"syscall"

	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

var errNotSocket = errors.New("not a socket")

func shutdownWritePolicy(stream relay.Stream) error {
	err := socketShutdownWrite(stream)
	if err == nil {
		return nil
	}
	if errors.Is(err, errNotSocket) || isNotSock(err) {
		return stream.ShutdownWrite()
	}
	return err
}

func isNotSock(err error) bool {
	return errors.Is(err, syscall.ENOTSOCK) || errors.Is(err, unix.ENOTSOCK)
}

func shutdownSyscallConn(sc syscall.Conn) error {
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var shutErr error
	if err := raw.Control(func(fd uintptr) {
		shutErr = ShutdownWrite(int(fd))
	}); err != nil {
		return err
	}
	return shutErr
}

func socketShutdownWrite(stream relay.Stream) error {
	var cur any = stream
	for hops := 0; hops < 16 && cur != nil; hops++ {
		if sc, ok := cur.(syscall.Conn); ok {
			return shutdownSyscallConn(sc)
		}
		switch x := cur.(type) {
		case relay.NetStream:
			cur = x.Conn
		case relay.FDStream:
			for _, v := range []any{x.W, x.C, x.R} {
				if sc, ok := v.(syscall.Conn); ok {
					return shutdownSyscallConn(sc)
				}
			}
			return errNotSocket
		case relay.RWCStream:
			cur = x.ReadWriteCloser
		default:
			u, ok := cur.(interface{ UnwrapStream() relay.Stream })
			if !ok {
				return errNotSocket
			}
			next := u.UnwrapStream()
			if next == nil || next == cur {
				return errNotSocket
			}
			cur = next
		}
	}
	return errNotSocket
}
