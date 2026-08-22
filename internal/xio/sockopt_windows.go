//go:build windows

package xio

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/windows"
)

const (
	solSocket   = windows.SOL_SOCKET
	soReuseaddr = windows.SO_REUSEADDR
	soReuseport = 0
	ipprotoIPv6 = windows.IPPROTO_IPV6
	ipv6V6only  = windows.IPV6_V6ONLY
	soRcvtimeo  = windows.SO_RCVTIMEO
	// x/sys/windows does not currently expose Winsock's SO_SNDTIMEO.
	soSndtimeo = 0x1005
)

func setSockoptInt(fd, level, opt, value int) error {
	return windows.SetsockoptInt(windows.Handle(fd), level, opt, value)
}

func SetSockoptInt(fd, level, opt, value int) error {
	return setSockoptInt(fd, level, opt, value)
}

func setListenBacklog(fd, backlog int) error {
	return windows.Listen(windows.Handle(fd), backlog)
}

// ApplySocketTimeos applies rcvtimeo=/sndtimeo= using Winsock's millisecond
// DWORD values. Zero disables the timeout; positive sub-millisecond values are
// rounded up so they do not turn into zero accidentally.
func ApplySocketTimeos(fd int, s parse.Spec) error {
	if v := s.OptionValue("rcvtimeo", ""); v != "" {
		ms, err := windowsTimeoutMillis(v)
		if err != nil {
			return fmt.Errorf("rcvtimeo: %w", err)
		}
		if err := windows.SetsockoptInt(windows.Handle(fd), solSocket, soRcvtimeo, int(ms)); err != nil {
			return fmt.Errorf("rcvtimeo: %w", err)
		}
	}
	if v := s.OptionValue("sndtimeo", ""); v != "" {
		ms, err := windowsTimeoutMillis(v)
		if err != nil {
			return fmt.Errorf("sndtimeo: %w", err)
		}
		if err := windows.SetsockoptInt(windows.Handle(fd), solSocket, soSndtimeo, int(ms)); err != nil {
			return fmt.Errorf("sndtimeo: %w", err)
		}
	}
	return nil
}

func windowsTimeoutMillis(v string) (uint32, error) {
	d, err := parseTimeval(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid timeout %q", v)
	}
	if d == 0 {
		return 0, nil
	}
	ms := (uint64(d) + uint64(time.Millisecond) - 1) / uint64(time.Millisecond)
	if ms > math.MaxUint32 {
		return 0, fmt.Errorf("timeout %q exceeds Winsock's DWORD milliseconds", v)
	}
	return uint32(ms), nil
}

func applyIPTTLTOS(fd int, s parse.Spec, network string) error {
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return nil
	}
	is6 := strings.HasSuffix(network, "6")
	option := func(names ...string) (string, bool) {
		for _, name := range names {
			if o, ok := s.OptionNamed(name); ok && o.Has && strings.TrimSpace(o.Value) != "" {
				return o.Value, true
			}
		}
		return "", false
	}
	if value, ok := option("ip-ttl", "ttl"); ok {
		n, err := ParseIntAny(value)
		if err != nil {
			return fmt.Errorf("ip-ttl: %w", err)
		}
		level, opt := windows.IPPROTO_IP, windows.IP_TTL
		if is6 {
			level, opt = windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS
		}
		if err := windows.SetsockoptInt(windows.Handle(fd), level, opt, n); err != nil {
			return fmt.Errorf("ip-ttl: %w", err)
		}
	}
	if value, ok := option("ip-tos", "tos"); ok && !is6 {
		n, err := ParseIntAny(value)
		if err != nil {
			return fmt.Errorf("ip-tos: %w", err)
		}
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TOS, n); err != nil {
			return fmt.Errorf("ip-tos: %w", err)
		}
	}
	return nil
}
