//go:build linux || darwin

package xio

import (
	"errors"
	"fmt"
	"math"

	"github.com/oittaa/socat/internal/parse"
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

// applyLingerOption sets SO_LINGER (onoff=1) from a non-negative seconds value.
func applyLingerOption(fd int, o parse.Option) error {
	if !o.Has {
		return fmt.Errorf("so-linger: requires a value")
	}
	seconds, err := ParseIntAny(o.Value)
	if err != nil || seconds < 0 {
		return fmt.Errorf("so-linger: invalid value %q", o.Value)
	}
	if seconds > math.MaxInt32 {
		return fmt.Errorf("so-linger: value %q is out of range", o.Value)
	}
	linger := &unix.Linger{
		Onoff:  1,
		Linger: int32(seconds), // #nosec G115 -- bounded by MaxInt32 above
	}
	if err := unix.SetsockoptLinger(fd, solSocket, unix.SO_LINGER, linger); err != nil {
		return fmt.Errorf("so-linger: %w", err)
	}
	return nil
}

// applySocketTimeoOption is one rcvtimeo=/sndtimeo= occurrence as kernel
// SO_RCVTIMEO / SO_SNDTIMEO. Only raw blocking-fd paths observe these; Go
// netpoll conns run nonblocking, so use read/write deadlines at the call site.
func applySocketTimeoOption(fd int, o parse.Option) error {
	tv, err := timevalFromSpec(o.Value)
	if err != nil {
		return fmt.Errorf("%s: %w", o.Name, err)
	}
	opt := soRcvtimeo
	if o.Name == "sndtimeo" {
		opt = soSndtimeo
	}
	if err := unix.SetsockoptTimeval(fd, solSocket, opt, tv); err != nil {
		return fmt.Errorf("%s: %w", o.Name, err)
	}
	return nil
}

func timevalFromSpec(v string) (*unix.Timeval, error) {
	d, err := parseTimeval(v)
	if err != nil || d < 0 {
		return nil, fmt.Errorf("invalid timeout %q", v)
	}
	// NsecToTimeval handles each platform's Sec/Usec widths.
	tv := unix.NsecToTimeval(int64(d))
	return &tv, nil
}
