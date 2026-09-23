//go:build windows

package sockopt

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/windows"
)

const (
	SOLSocket   = windows.SOL_SOCKET
	SOReuseaddr = windows.SO_REUSEADDR
	SOReuseport = 0
	IPProtoIPv6 = windows.IPPROTO_IPV6
	IPv6V6Only  = windows.IPV6_V6ONLY
	soRcvtimeo  = windows.SO_RCVTIMEO
	soSndtimeo  = windows.SO_SNDTIMEO
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

func SetSockoptInt(fd, level, opt, value int) error {
	return windows.SetsockoptInt(windows.Handle(fd), level, opt, value)
}

func setSockoptBytes(fd, level, opt int, value []byte) error {
	if level < math.MinInt32 || level > math.MaxInt32 {
		return fmt.Errorf("setsockopt: level out of range")
	}
	if opt < math.MinInt32 || opt > math.MaxInt32 {
		return fmt.Errorf("setsockopt: opt out of range")
	}
	valLen := len(value)
	if valLen < 0 || valLen > math.MaxInt32 {
		return fmt.Errorf("setsockopt: value too long")
	}
	var p *byte
	if valLen > 0 {
		p = &value[0]
	}
	return windows.Setsockopt(windows.Handle(fd), int32(level), int32(opt), p, int32(valLen))
}

func applyLingerSeconds(fd int, seconds int) error {
	if seconds < 0 {
		return fmt.Errorf("so-linger: invalid value %q", fmt.Sprint(seconds))
	}
	if seconds > math.MaxUint16 {
		return fmt.Errorf("so-linger: value %q is out of range", fmt.Sprint(seconds))
	}
	linger := &windows.Linger{Onoff: 1, Linger: int32(seconds)}
	if int(linger.Linger) != seconds {
		return fmt.Errorf("so-linger: value %q is out of range", fmt.Sprint(seconds))
	}
	if err := windows.SetsockoptLinger(windows.Handle(fd), SOLSocket, windows.SO_LINGER, linger); err != nil {
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
	ms, err := windowsTimeoutMillisFromDuration(action.Duration)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	opt := soRcvtimeo
	if !action.Recv {
		opt = soSndtimeo
	}
	if err := windows.SetsockoptInt(windows.Handle(fd), SOLSocket, opt, int(ms)); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func windowsTimeoutMillisFromDuration(d time.Duration) (uint32, error) {
	if d < 0 {
		return 0, fmt.Errorf("invalid timeout %q", d)
	}
	if d == 0 {
		return 0, nil
	}
	ms := (uint64(d) + uint64(time.Millisecond) - 1) / uint64(time.Millisecond)
	if ms > math.MaxUint32 {
		return 0, fmt.Errorf("timeout %q exceeds Winsock's DWORD milliseconds", d)
	}
	return uint32(ms), nil
}
