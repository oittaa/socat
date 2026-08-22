//go:build unix

package xio

import (
	"fmt"

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
)

func setSockoptInt(fd, level, opt, value int) error {
	return unix.SetsockoptInt(fd, level, opt, value)
}

func SetSockoptInt(fd, level, opt, value int) error {
	return setSockoptInt(fd, level, opt, value)
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

func timevalFromSpec(v string) (*unix.Timeval, error) {
	d, err := parseTimeval(v)
	if err != nil || d < 0 {
		return nil, fmt.Errorf("invalid timeout %q", v)
	}
	// NsecToTimeval handles each platform's Sec/Usec widths.
	tv := unix.NsecToTimeval(int64(d))
	return &tv, nil
}
