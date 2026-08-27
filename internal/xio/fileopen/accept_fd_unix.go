//go:build unix

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

// openAcceptFDNum implements classic ACCEPT-FD / ACCEPT on Unix.
//
// Classic: xioopen_accept_fd in xio-fdnum.c then _xioopen_accept_fd in
// xio-listen.c (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same).
// Parse fd; F_SETFD FD_CLOEXEC (warn); getsockname (warn); Accept; xiocheckpeer
// (range/sourceport/lowport/tcpwrap); CloseRefused peer and continue; fork
// keeps the listen fd else close it and use the accepted socket; applyopts
// PH_FD / PH_PASTSOCKET / PH_CONNECTED; SOCK/PEER env.
//
// Man lists groups FD, SOCKET, TCP, CHILD, RETRY. C addrdesc is
// GROUP_FD|GROUP_SOCKET|GROUP_SOCK_UNIX|GROUP_SOCK_IP|GROUP_IPAPP|GROUP_CHILD|
// GROUP_RANGE|GROUP_RETRY. GROUP_IPAPP is the C union of UDP, TCP, SCTP,
// DCCP, and UDP-Lite (xioopts.h); it is broader than man GROUP_TCP, not a
// short form of TCP. This is a man/C group discrepancy: we follow C so
// documented useful options (fork, range, sourceport, lowport, tcpwrap)
// work for IP and UNIX listeners. ACCEPT is the public addressnames[] alias.
// The fd must already be a listening stream socket; we accept(2) on it.
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
			return xio.WrapAccepted(s, c, func(c net.Conn) error {
				return applyAcceptFDAcceptedOpts(s, c)
			})
		},
	})
}

// fileListenerFromFD wraps a listening stream socket. net.FileListener dups
// the fd; closing the *os.File afterwards does not affect the Listener (Go
// net.FileListener docs). Classic then owns that listen fd until a non-fork
// accept closes it (OpenListenSession) or process exit.
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
	// Classic _xioopen_accept_fd does not probe SO_ACCEPTCONN; it accept(2)s.
	// Linux reports listening==0 for a connected socket. Darwin ExtraFiles
	// TCP listeners often return ENOPROTOOPT ("protocol not available") for
	// the probe (filan treats SO_ACCEPTCONN the same way). Skip only those
	// "option unsupported" errors and let FileListener reject non-listeners.
	listening, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	switch {
	case err == nil && listening == 0:
		return nil, fmt.Errorf("ACCEPT-FD:%d: socket is connected or not listening", fd)
	case err != nil && !acceptConnProbeUnsupported(err):
		return nil, fmt.Errorf("ACCEPT-FD:%d: %w", fd, err)
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

func applyAcceptFDAcceptedOpts(s parse.Spec, c net.Conn) error {
	if sc, ok := c.(syscall.Conn); ok {
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
