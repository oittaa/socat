//go:build unix

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

// ApplySocketTimeos applies classic rcvtimeo=/sndtimeo= as kernel
// SO_RCVTIMEO/SO_SNDTIMEO (TYPE_TIMEVAL, SOL_SOCKET), matching xioopts.c's
// IF_SOCKET handling. Only raw blocking-fd paths observe these on our port —
// Go netpoll conns run nonblocking, where the equivalent is read/write
// deadlines at the call site.
func ApplySocketTimeos(fd int, s parse.Spec) error {
	if v := s.OptionValue("rcvtimeo", ""); v != "" {
		tv, err := timevalFromSpec(v)
		if err != nil {
			return fmt.Errorf("rcvtimeo: %w", err)
		}
		if err := unix.SetsockoptTimeval(fd, solSocket, soRcvtimeo, tv); err != nil {
			return fmt.Errorf("rcvtimeo: %w", err)
		}
	}
	if v := s.OptionValue("sndtimeo", ""); v != "" {
		tv, err := timevalFromSpec(v)
		if err != nil {
			return fmt.Errorf("sndtimeo: %w", err)
		}
		if err := unix.SetsockoptTimeval(fd, solSocket, soSndtimeo, tv); err != nil {
			return fmt.Errorf("sndtimeo: %w", err)
		}
	}
	return nil
}

// ApplySocketOptionsWithoutGeneric applies fixed SOL_SOCKET options but leaves
// command-ordered named and generic setsockopt actions untouched. PH_ALL
// constructors such as SOCKETPAIR apply those together afterward.
func ApplySocketOptionsWithoutGeneric(fd int, s parse.Spec) error {
	if err := ApplySocketTimeos(fd, s); err != nil {
		return err
	}
	if value, ok := optionValueAny(s, "so-linger", "linger"); ok {
		seconds, err := ParseIntAny(value)
		if err != nil || seconds < 0 {
			return fmt.Errorf("so-linger: invalid value %q", value)
		}
		if seconds > math.MaxInt32 {
			return fmt.Errorf("so-linger: value %q is out of range", value)
		}
		linger := &unix.Linger{
			Onoff:  1,
			Linger: int32(seconds), // #nosec G115 -- bounded by MaxInt32 above
		}
		if err := unix.SetsockoptLinger(fd, solSocket, unix.SO_LINGER, linger); err != nil {
			return fmt.Errorf("so-linger: %w", err)
		}
	}
	return applyPastSocketBuffersAndDeviceWithoutGeneric(fd, s)
}

// ApplySocketOptions applies the SOL_SOCKET options shared by raw descriptors
// and Go net sockets, including generic PH_PASTSOCKET actions.
func ApplySocketOptions(fd int, s parse.Spec) error {
	if err := ApplySocketOptionsWithoutGeneric(fd, s); err != nil {
		return err
	}
	return applyOrderedPastSocketPhaseOptions(fd, s, "")
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
