package xio

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// ApplyReuse sets SO_REUSEADDR and optional SO_REUSEPORT on fd.
// reuseaddrDefault is the classic listen default (true for TCP/UDP listen).
func ApplyReuse(fd int, s parse.Spec, reuseaddrDefault bool) {
	reuse := reuseaddrDefault
	if s.HasOption("reuseaddr") {
		reuse = s.BoolOption("reuseaddr")
	}
	if reuse {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}
	if s.BoolOption("reuseport") {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}
}

func StripBrackets(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

func IsAbstract(path string) bool {
	return len(path) > 0 && (path[0] == 0 || path[0] == '@')
}

func HostPortParams(s parse.Spec) (host, port string, err error) {
	if len(s.Params) < 2 {
		// Maybe host:port as one param was split wrong, or combined
		if len(s.Params) == 1 {
			h, p, e := net.SplitHostPort(s.Params[0])
			if e == nil {
				return h, p, nil
			}
		}
		return "", "", fmt.Errorf("%s requires host and port", s.Type)
	}
	return s.Params[0], s.Params[1], nil
}

func BindPort(bind, sourceport string) string {
	if strings.Contains(bind, ":") {
		// might already be host:port or [ipv6]:port
		if _, _, err := net.SplitHostPort(bind); err == nil {
			return bind
		}
	}
	return net.JoinHostPort(StripBrackets(bind), sourceport)
}

func ConnectTimeout(s parse.Spec) time.Duration {
	v := s.OptionValue("connect-timeout", "")
	if v == "" {
		return 0
	}
	return ParseTimeval(v)
}

func ListenNetwork(g *Global, s parse.Spec) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		switch strings.ToLower(pf) {
		case "ip4", "ipv4", "inet", "4":
			return "tcp4"
		case "ip6", "ipv6", "inet6", "6":
			return "tcp6"
		}
	}
	switch g.IPVersion {
	case IPv4:
		return "tcp4"
	case IPv6:
		return "tcp6"
	case IPvAny:
		return "tcp"
	}
	// IPvDefault: honor listen env, else IPv4
	if v := strings.TrimSpace(os.Getenv("SOCAT_DEFAULT_LISTEN_IP")); v != "" {
		switch strings.ToLower(v) {
		case "4", "ip4", "ipv4":
			return "tcp4"
		case "6", "ip6", "ipv6":
			return "tcp6"
		}
	}
	return "tcp4"
}

func AcceptTimeout(s parse.Spec) time.Duration {
	v := s.OptionValue("accept-timeout", "")
	if v == "" {
		return 0
	}
	return ParseTimeval(v)
}

func IsTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout") ||
		strings.Contains(strings.ToLower(err.Error()), "i/o timeout")
}

// ApplySetsockoptFD parses classic setsockopt=level:optname:value (ints) and applies it.
// SETSOCKOPT test uses setsockopt=6:TCP_MAXSEG:512 (IPPROTO_TCP + TCP_MAXSEG).
func ApplyTCPConnOpts(s parse.Spec, c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	if s.BoolOption("keepalive") || s.BoolOption("so-keepalive") || s.HasOption("keepidle") {
		_ = tc.SetKeepAlive(true)
	}
	if s.BoolOption("nodelay") || s.BoolOption("tcp-nodelay") {
		_ = tc.SetNoDelay(true)
	}
}

func ApplySetsockoptFD(fd int, spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) < 3 {
		return fmt.Errorf("setsockopt requires level:optname:value")
	}
	level, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("setsockopt level: %w", err)
	}
	opt, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("setsockopt optname: %w", err)
	}
	val, err := strconv.Atoi(parts[2])
	if err != nil {
		return fmt.Errorf("setsockopt value: %w", err)
	}
	return syscall.SetsockoptInt(fd, level, opt, val)
}

// FormatSocatAddr matches classic env formatting (IPv6 in brackets).

func NetworkTCP(g *Global, s parse.Spec, def string) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		switch strings.ToLower(pf) {
		case "ip4", "ipv4", "inet", "4":
			return "tcp4"
		case "ip6", "ipv6", "inet6", "6":
			return "tcp6"
		}
	}
	switch g.IPVersion {
	case IPv4:
		return "tcp4"
	case IPv6:
		return "tcp6"
	case IPvAny:
		return "tcp"
	default: // IPvDefault
		if def != "" {
			return def
		}
		return "tcp4" // classic default since 1.8.0.1
	}
}

// NetworkTCPForHost picks tcp/tcp4/tcp6 using options, then host literal shape.
func NetworkTCPForHost(g *Global, s parse.Spec, host string) string {
	// Explicit pf / global version first (except when host is clearly the other family)
	n := NetworkTCP(g, s, "")
	h := StripBrackets(host)
	if ip := net.ParseIP(h); ip != nil {
		if ip.To4() != nil {
			return "tcp4"
		}
		return "tcp6"
	}
	if strings.Contains(h, ":") {
		return "tcp6"
	}
	if n != "" {
		return n
	}
	return "tcp4"
}

func ParsePositiveInt(v string) (int, error) {
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid")
	}
	return n, nil
}

func FirstHost(s parse.Spec) string {
	if len(s.Params) > 0 {
		return s.Params[0]
	}
	return ""
}

func ParseTimeval(v string) time.Duration {
	// classic timeval: seconds with optional fractional part
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		d, err2 := time.ParseDuration(v)
		if err2 != nil {
			return 0
		}
		return d
	}
	return time.Duration(f * float64(time.Second))
}
