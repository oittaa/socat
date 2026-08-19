package xio

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// preferredResolveVersion applies the classic resolver preference. Explicit
// -4, -6, and -0 settings in Global take precedence over the environment.
func preferredResolveVersion(g *Global) IPVersion {
	if g != nil && g.IPVersion != IPv4Default {
		return g.IPVersion
	}
	switch strings.TrimSpace(os.Getenv("SOCAT_PREFERRED_RESOLVE_IP")) {
	case "0":
		return IPvAny
	case "6":
		return IPv6
	case "4":
		return IPv4
	default:
		return IPv4Default
	}
}

// WaitFromEnv implements classic's integer-second diagnostic wait variables.
// Invalid, zero, and negative values are treated like atoi(...)=0.
func WaitFromEnv(name string) {
	if delay := environmentWaitDuration(os.Getenv(name)); delay > 0 {
		time.Sleep(delay)
	}
}

func environmentWaitDuration(value string) time.Duration {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	maxSeconds := int64((1<<63 - 1) / time.Second)
	if seconds > maxSeconds {
		seconds = maxSeconds
	}
	return time.Duration(seconds) * time.Second
}
