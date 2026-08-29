package xio

import (
	"errors"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// Named SOL_SOCKET, TCP, and Linux SCTP integer socket options.
// Bare flag → 1. Kernel rejection fails the call. Linux SO_SNDLOWAT is
// recognized but rejected (kernel ENOPROTOOPT). nopush/noopt work on Darwin;
// Linux and Windows reject. so-bsdcompat, tcp-info, tcp-md5sig, and
// sctp-maxseg-late are not implemented. sctp-nodelay/sctp-maxseg use SOL_SCTP.
var errNamedOptUnsupported = errors.New("not supported on this platform")

func parseTypeIntSockopt(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := ParseIntAny(o.Value)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value %q", o.Name, o.Value)
	}
	return n, nil
}

func applyNamedIntSockopt(fd int, o parse.Option, level, opt int) error {
	n, err := parseTypeIntSockopt(o)
	if err != nil {
		return err
	}
	if err := setSockoptInt(fd, level, opt, n); err != nil {
		return fmt.Errorf("%s: %w", o.Name, err)
	}
	return nil
}

// applyNamedPastSocketSockopt applies one named SOL_SOCKET, TCP, or Linux
// SCTP integer option after socket(). Callers walk Spec.Options so named,
// fixed (broadcast/sndbuf/linger/…), generic setsockopt-socket, and IP
// options retain command-line order.
func applyNamedPastSocketSockopt(fd int, o parse.Option) (bool, error) {
	level, opt, ok, err := lookupNamedPastSocketInt(o.Name)
	if !ok {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("%s: %w", o.Name, err)
	}
	return true, applyNamedIntSockopt(fd, o, level, opt)
}

// applyNamedConnectedSockopt applies named TCP options after connect
// (tcp-maxseg-late). ApplyGenericSetsockopt's connected walk calls it so
// TLS/WS/proxy/SOCKS (ApplyTCPConnOpts) and WrapCommon fallbacks share one
// pass and do not apply connected generic setsockopt twice.
func applyNamedConnectedSockopt(fd int, o parse.Option) (bool, error) {
	level, opt, ok, err := lookupNamedConnectedInt(o.Name)
	if !ok {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("%s: %w", o.Name, err)
	}
	return true, applyNamedIntSockopt(fd, o, level, opt)
}

func hasNamedConnectedTCP(s parse.Spec) bool {
	for _, o := range s.Options {
		if _, _, ok, _ := lookupNamedConnectedInt(o.Name); ok {
			return true
		}
	}
	return false
}

func namedConnectedTCPName(name string) bool {
	_, _, ok, _ := lookupNamedConnectedInt(name)
	return ok
}
