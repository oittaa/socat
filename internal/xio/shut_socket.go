package xio

import (
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/relay"
)

// shutdownWritePolicy issues shutdown(fd, SHUT_WR) on the underlying socket.
// It does not fall back to Stream.ShutdownWrite: that would CloseWrite a pipe
// or send TLS close-notify. Non-sockets return ENOTSOCK/WSAENOTSOCK.
// Wrappers that hide the fd (crypto/tls.Conn, rcvtimeo) must expose NetConn().
// Windows probes SO_TYPE first so a pipe returns WSAENOTSOCK, not WSAENOTCONN.
func shutdownWritePolicy(stream relay.Stream) error {
	return shutdownFrom(stream)
}

func shutdownFrom(cur any) error {
	for hops := 0; hops < 16 && cur != nil; hops++ {
		if sc := socketConnOf(cur); sc != nil {
			return shutdownSyscallConn(sc)
		}
		switch x := cur.(type) {
		case relay.NetStream:
			cur = x.Conn
		case relay.FDStream:
			var last error
			for _, v := range []any{x.W, x.C, x.R} {
				if v == nil {
					continue
				}
				err := shutdownFrom(v)
				if err == nil {
					return nil
				}
				last = err
				if !isNotSock(err) {
					return err
				}
			}
			if last != nil {
				return last
			}
			return notSocketError()
		case relay.RWCStream:
			cur = x.ReadWriteCloser
		default:
			u, ok := cur.(interface{ UnwrapStream() relay.Stream })
			if !ok {
				return notSocketError()
			}
			next := u.UnwrapStream()
			if next == nil || next == cur {
				return notSocketError()
			}
			cur = next
		}
	}
	return notSocketError()
}

func socketConnOf(v any) syscall.Conn {
	for hops := 0; hops < 8 && v != nil; hops++ {
		if sc, ok := v.(syscall.Conn); ok {
			return sc
		}
		unwrapper, ok := v.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		next := unwrapper.NetConn()
		if next == nil || next == v {
			return nil
		}
		v = next
	}
	return nil
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
