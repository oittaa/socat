//go:build windows

package xio

import (
	"errors"
	"fmt"
	"math"
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
	soDebug     = 0x0001 // Winsock SO_DEBUG; x/sys/windows does not export it
	soDontroute = windows.SO_DONTROUTE
	soOobinline = 0x0100 // Winsock SO_OOBINLINE; x/sys/windows does not export it
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

// applyLingerOption is classic opt_so_linger (PH_PASTSOCKET, TYPE_INT).
func applyLingerOption(fd int, o parse.Option) error {
	if !o.Has {
		return fmt.Errorf("so-linger: requires a value")
	}
	seconds, err := ParseIntAny(o.Value)
	if err != nil || seconds < 0 {
		return fmt.Errorf("so-linger: invalid value %q", o.Value)
	}
	if seconds > math.MaxUint16 {
		return fmt.Errorf("so-linger: value %q is out of range", o.Value)
	}
	linger := &windows.Linger{Onoff: 1, Linger: int32(seconds)}
	if int(linger.Linger) != seconds {
		return fmt.Errorf("so-linger: value %q is out of range", o.Value)
	}
	if err := windows.SetsockoptLinger(windows.Handle(fd), solSocket, windows.SO_LINGER, linger); err != nil {
		return fmt.Errorf("so-linger: %w", err)
	}
	return nil
}

// applySocketTimeoOption is one rcvtimeo=/sndtimeo= occurrence.
func applySocketTimeoOption(fd int, o parse.Option) error {
	ms, err := windowsTimeoutMillis(o.Value)
	if err != nil {
		return fmt.Errorf("%s: %w", o.Name, err)
	}
	opt := soRcvtimeo
	if o.Name == "sndtimeo" {
		opt = soSndtimeo
	}
	if err := windows.SetsockoptInt(windows.Handle(fd), solSocket, opt, int(ms)); err != nil {
		return fmt.Errorf("%s: %w", o.Name, err)
	}
	return nil
}

// ApplySocketOptionsWithoutGeneric is kept for SOCKETPAIR / network
// constructors that still split PH_ALL around the generic walk. All
// PH_PASTSOCKET action options now live in applyOrderedPastSocketPhaseOptions
// and ApplyGenericSetsockoptAll, so this helper is a no-op.
func ApplySocketOptionsWithoutGeneric(_ int, _ parse.Spec) error {
	return nil
}

// ApplySocketOptions applies the SOL_SOCKET options shared by raw descriptors
// and Go net sockets, including generic PH_PASTSOCKET actions.
func ApplySocketOptions(fd int, s parse.Spec) error {
	if err := ApplySocketOptionsWithoutGeneric(fd, s); err != nil {
		return err
	}
	return applyOrderedPastSocketPhaseOptions(fd, s, "")
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
