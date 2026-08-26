//go:build windows

package xio

import (
	"errors"
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
	soSndtimeo  = 0x1005
	soSndbuf    = windows.SO_SNDBUF
	soRcvbuf    = windows.SO_RCVBUF
	soKeepalive = windows.SO_KEEPALIVE
	soBroadcast = windows.SO_BROADCAST
)

func isNotSocketError(err error) bool {
	return errors.Is(err, windows.WSAENOTSOCK)
}

func setSockoptInt(fd, level, opt, value int) error {
	recordSockoptInt(fd, level, opt, value)
	return windows.SetsockoptInt(windows.Handle(fd), level, opt, value)
}

func setSockoptBytes(fd, level, opt int, value []byte) error {
	recordSockoptBytes(fd, level, opt, value)
	if level < math.MinInt32 || level > math.MaxInt32 || opt < math.MinInt32 || opt > math.MaxInt32 {
		return fmt.Errorf("setsockopt: level or opt out of range")
	}
	if len(value) > math.MaxInt32 {
		return fmt.Errorf("setsockopt: value too long")
	}
	var p *byte
	if len(value) > 0 {
		p = &value[0]
	}
	return windows.Setsockopt(windows.Handle(fd), int32(level), int32(opt), p, int32(len(value)))
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

// ApplySocketOptions applies the SOL_SOCKET options shared by raw descriptors
// and Go net sockets.
func ApplySocketOptions(fd int, s parse.Spec) error {
	if err := ApplySocketTimeos(fd, s); err != nil {
		return err
	}
	if value, ok := optionValueAny(s, "so-linger", "linger"); ok {
		seconds, err := ParseIntAny(value)
		if err != nil || seconds < 0 {
			return fmt.Errorf("so-linger: invalid value %q", value)
		}
		if seconds > math.MaxUint16 {
			return fmt.Errorf("so-linger: value %q is out of range", value)
		}
		linger := &windows.Linger{Onoff: 1, Linger: int32(seconds)}
		if int(linger.Linger) != seconds {
			return fmt.Errorf("so-linger: value %q is out of range", value)
		}
		if err := windows.SetsockoptLinger(windows.Handle(fd), solSocket, windows.SO_LINGER, linger); err != nil {
			return fmt.Errorf("so-linger: %w", err)
		}
	}
	return applyPastSocketBuffersAndDevice(fd, s)
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
