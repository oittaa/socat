//go:build linux || darwin

package xio

import (
	"errors"
	"fmt"
	"math"

	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

const (
	solSocket   = unix.SOL_SOCKET
	soReuseaddr = unix.SO_REUSEADDR
	soReuseport = unix.SO_REUSEPORT
	ipprotoIPv6 = unix.IPPROTO_IPV6
	ipv6V6only  = unix.IPV6_V6ONLY
	soRcvtimeo  = unix.SO_RCVTIMEO
	soSndtimeo  = unix.SO_SNDTIMEO
	soSndbuf    = unix.SO_SNDBUF
	soRcvbuf    = unix.SO_RCVBUF
	soKeepalive = unix.SO_KEEPALIVE
	soBroadcast = unix.SO_BROADCAST
	soDebug     = unix.SO_DEBUG
	soDontroute = unix.SO_DONTROUTE
	soOobinline = unix.SO_OOBINLINE
)

func isNotSocketError(err error) bool {
	return errors.Is(err, unix.ENOTSOCK)
}

func setSockoptInt(fd, level, opt, value int) error {
	recordSockoptInt(fd, level, opt, value)
	return unix.SetsockoptInt(fd, level, opt, value)
}

func setSockoptBytes(fd, level, opt int, value []byte) error {
	recordSockoptBytes(fd, level, opt, value)
	return unix.SetsockoptString(fd, level, opt, string(value))
}

func setSockoptByte(fd, level, opt int, value byte) error {
	recordSockoptBytes(fd, level, opt, []byte{value})
	return unix.SetsockoptByte(fd, level, opt, value)
}

func setSockoptInet4Addr(fd, level, opt int, value [4]byte) error {
	recordSockoptBytes(fd, level, opt, value[:])
	return unix.SetsockoptInet4Addr(fd, level, opt, value)
}

func SetSockoptInt(fd, level, opt, value int) error {
	return setSockoptInt(fd, level, opt, value)
}

func setListenBacklog(fd, backlog int) error {
	return unix.Listen(fd, backlog)
}

func applyLingerSeconds(fd int, seconds int) error {
	if seconds < 0 {
		return fmt.Errorf("so-linger: invalid value %q", fmt.Sprint(seconds))
	}
	if seconds > math.MaxInt32 {
		return fmt.Errorf("so-linger: value %q is out of range", fmt.Sprint(seconds))
	}
	linger := &unix.Linger{
		Onoff:  1,
		Linger: int32(seconds),
	}
	if err := unix.SetsockoptLinger(fd, solSocket, unix.SO_LINGER, linger); err != nil {
		return fmt.Errorf("so-linger: %w", err)
	}
	return nil
}

func applySocketTimeoDuration(fd int, action addrconfig.SocketAction) error {
	name := action.Text
	if name == "" {
		if action.Recv {
			name = "rcvtimeo"
		} else {
			name = "sndtimeo"
		}
	}
	d := action.Duration
	if d < 0 {
		return fmt.Errorf("%s: invalid timeout %q", name, d)
	}
	tv := unix.NsecToTimeval(int64(d))
	opt := soRcvtimeo
	if !action.Recv {
		opt = soSndtimeo
	}
	if err := unix.SetsockoptTimeval(fd, solSocket, opt, &tv); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
