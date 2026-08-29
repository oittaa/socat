//go:build linux || darwin

package fileopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func init() {
	xio.FeatureACCEPTFD = true
}

// openAcceptFDNum implements ACCEPT-FD / ACCEPT on Linux and macOS.
// The fd must already be a listening stream socket. After accept, apply
// descriptor, socket, and connected options; WrapCommon applies late options.
// fork, range, sourceport, lowport, and tcpwrap apply to IP and UNIX
// listeners, not only TCP. ACCEPT is the public alias of ACCEPT-FD.
func openAcceptFDNum(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, fd int) (*xio.Opened, error) {
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		if g != nil && g.Log != nil {
			g.Log.Warningf("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", fd, err)
		}
	}
	if _, err := unix.Getsockname(fd); err != nil {
		if g != nil && g.Log != nil {
			g.Log.Warningf("getsockname(fd=%d, ...): %s", fd, err)
		}
	}

	ln, err := fileListenerFromFD(fd)
	if err != nil {
		return nil, err
	}
	if g != nil && g.Log != nil {
		g.Log.Noticef("using file descriptor %d accepting a connection", fd)
	}
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    fmt.Sprintf("%s:%d", s.Type, fd),
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			if err := applyAcceptFDAcceptedOpts(s, c); err != nil {
				return nil, err
			}
			// After open, after socket(), and after connect/accept already
			// ran. Skip them here so late is not applied early.
			return xio.WrapCommonAfterConnectedFDPhaseApplied(s, relay.NetStream{Conn: c})
		},
	})
}

// fileListenerFromFD wraps a listening stream socket. net.FileListener dups
// the fd; closing the *os.File afterwards does not affect the Listener.
// OpenListenSession owns that listen fd until a non-fork accept closes it
// or the process exits.
func fileListenerFromFD(fd int) (net.Listener, error) {
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return nil, fmt.Errorf("ACCEPT-FD:%d: not a socket: %w", fd, err)
	}
	switch typ {
	case unix.SOCK_DGRAM:
		return nil, fmt.Errorf("ACCEPT-FD:%d: datagram sockets are not supported", fd)
	case unix.SOCK_STREAM, unix.SOCK_SEQPACKET:
	default:
		return nil, fmt.Errorf("ACCEPT-FD:%d: unsupported socket type %d", fd, typ)
	}
	if err := rejectIfNotListening(fd); err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("accept-fd:%d", fd))
	if f == nil {
		return nil, fmt.Errorf("ACCEPT-FD:%d invalid", fd)
	}
	ln, err := net.FileListener(f)
	logx.CloseQuiet(f)
	if err != nil {
		return nil, fmt.Errorf("ACCEPT-FD:%d: not a listening stream socket: %w", fd, err)
	}
	return ln, nil
}

func acceptConnProbeUnsupported(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EPROTONOSUPPORT)
}

// rejectIfNotListening rejects a connected or never-listen()ed stream socket.
// Linux SO_ACCEPTCONN is 0 for a connected socket. macOS ExtraFiles TCP
// listeners often return ENOPROTOOPT; FileListener would then wrap a
// connected TCP fd and Accept returns EINVAL. A listener has no peer
// (getpeername → ENOTCONN); a connected socket does.
func rejectIfNotListening(fd int) error {
	listening, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	switch {
	case err == nil && listening == 0:
		return fmt.Errorf("ACCEPT-FD:%d: socket is connected or not listening", fd)
	case err == nil:
		return nil
	case !acceptConnProbeUnsupported(err):
		return fmt.Errorf("ACCEPT-FD:%d: %w", fd, err)
	}
	_, err = unix.Getpeername(fd)
	if err == nil {
		return fmt.Errorf("ACCEPT-FD:%d: socket is connected or not listening", fd)
	}
	if errors.Is(err, unix.ENOTCONN) {
		return nil
	}
	return fmt.Errorf("ACCEPT-FD:%d: %w", fd, err)
}

func applyAcceptFDAcceptedOpts(s parse.Spec, c net.Conn) error {
	if sc, ok := c.(syscall.Conn); ok {
		// After open, then after socket(), then after connect/accept.
		// Late is WrapCommon.
		if err := xio.ApplyFDPhaseLifecycleToConn(sc, s); err != nil {
			return err
		}
		raw, err := sc.SyscallConn()
		if err != nil {
			return err
		}
		var optErr error
		err = raw.Control(func(fd uintptr) {
			optErr = xio.ApplyPastSocketPhase(int(fd), s, acceptFDNetwork(c))
		})
		if err := errors.Join(err, optErr); err != nil {
			return err
		}
	}
	return xio.ApplyTCPConnOpts(s, c)
}

func acceptFDNetwork(c net.Conn) string {
	addr := c.LocalAddr()
	if addr == nil {
		addr = c.RemoteAddr()
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a.IP.To4() != nil {
			return "tcp4"
		}
		return "tcp6"
	case *net.UnixAddr:
		return "unix"
	default:
		if addr != nil {
			return addr.Network()
		}
		return ""
	}
}
