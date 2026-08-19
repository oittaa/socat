package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// ApplyReuse sets SO_REUSEADDR and optional SO_REUSEPORT on fd.
// reuseaddrDefault is the classic listen default (true for TCP/UDP listen).
func ApplyReuse(fd int, s parse.Spec, reuseaddrDefault bool) error {
	reuse := reuseaddrDefault
	if s.HasOption("reuseaddr") {
		reuse = s.BoolOption("reuseaddr")
	}
	if reuse {
		if err := setSockoptInt(fd, solSocket, soReuseaddr, 1); err != nil && s.HasOption("reuseaddr") {
			return fmt.Errorf("reuseaddr: %w", err)
		}
	}
	if s.BoolOption("reuseport") {
		if soReuseport == 0 {
			return fmt.Errorf("reuseport is not supported on this platform")
		}
		if err := setSockoptInt(fd, solSocket, soReuseport, 1); err != nil {
			return fmt.Errorf("reuseport: %w", err)
		}
	}
	return nil
}

// ApplyReuseAndV6Only sets listen reuse flags and IPV6_V6ONLY before bind.
func ApplyReuseAndV6Only(fd int, s parse.Spec, network string) error {
	if err := ApplyReuse(fd, s, true); err != nil {
		return err
	}
	switch network {
	case "tcp", "tcp6", "udp", "udp6":
	default:
		return nil
	}
	if s.HasOption("ipv6-v6only") {
		v := 0
		if s.BoolOption("ipv6-v6only") {
			v = 1
		}
		if err := setSockoptInt(fd, ipprotoIPv6, ipv6V6only, v); err != nil {
			return fmt.Errorf("ipv6-v6only: %w", err)
		}
		return nil
	}
	if network == "tcp" || network == "udp" {
		_ = setSockoptInt(fd, ipprotoIPv6, ipv6V6only, 0)
	}
	return nil
}

// ListenControl is a net.ListenConfig.Control that applies reuse and v6only.
func ListenControl(s parse.Spec) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var optionErr error
		controlErr := c.Control(func(fd uintptr) {
			optionErr = ApplyReuseAndV6Only(int(fd), s, network)
		})
		return errors.Join(controlErr, optionErr)
	}
}

// ListenBindHost is the wildcard bind when bind= is unset.
func ListenBindHost(network, bind string) string {
	if bind != "" {
		return bind
	}
	switch network {
	case "tcp4", "udp4", "ip4":
		return "0.0.0.0"
	default:
		return "::"
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

// pfVersion maps classic pf= names (and PF_* numbers) to a family.
var pfVersion = map[string]IPVersion{
	"4": IPv4, "ip4": IPv4, "ipv4": IPv4, "inet": IPv4, "2": IPv4, // 2 = PF_INET
	"6": IPv6, "ip6": IPv6, "ipv6": IPv6, "inet6": IPv6, "10": IPv6, // 10 = PF_INET6
}

// VersionFromPF maps a pf= value to IPv4 or IPv6.
func VersionFromPF(pf string) (IPVersion, bool) {
	v, ok := pfVersion[strings.ToLower(strings.TrimSpace(pf))]
	return v, ok
}

// NetworkFromPF maps pf= to a net package name (tcp4, udp6, ip4, …).
// Unknown pf returns def.
func NetworkFromPF(pf, proto, def string) string {
	v, ok := VersionFromPF(pf)
	if !ok {
		return def
	}
	switch v {
	case IPv4:
		return proto + "4"
	case IPv6:
		return proto + "6"
	default:
		return def
	}
}

func ListenNetwork(g *Global, s parse.Spec) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		if n := NetworkFromPF(pf, "tcp", ""); n != "" {
			return n
		}
	}
	ver := IPv4Default
	if g != nil {
		ver = g.IPVersion
	}
	switch ver {
	case IPv4:
		return "tcp4"
	case IPv6:
		return "tcp6"
	case IPvAny:
		return "tcp"
	}
	// IPv4Default: honor listen env, else IPv4
	if v := strings.TrimSpace(os.Getenv("SOCAT_DEFAULT_LISTEN_IP")); v != "" {
		if n := NetworkFromPF(v, "tcp", ""); n != "" {
			return n
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
	if os.IsTimeout(err) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ApplySetsockoptFD parses classic setsockopt=level:optname:value (ints) and applies it.
// SETSOCKOPT test uses setsockopt=6:TCP_MAXSEG:512 (IPPROTO_TCP + TCP_MAXSEG).
func ApplyTCPConnOpts(s parse.Spec, c net.Conn) error {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil
	}
	if s.HasOption("keepalive") || s.HasOption("so-keepalive") || s.HasOption("keepidle") {
		enabled := s.BoolOption("keepalive") || s.BoolOption("so-keepalive") || s.HasOption("keepidle")
		if err := tc.SetKeepAlive(enabled); err != nil {
			return fmt.Errorf("keepalive: %w", err)
		}
	}
	if s.HasOption("nodelay") || s.HasOption("tcp-nodelay") {
		enabled := s.BoolOption("nodelay") || s.BoolOption("tcp-nodelay")
		if err := tc.SetNoDelay(enabled); err != nil {
			return fmt.Errorf("nodelay: %w", err)
		}
	}
	return nil
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
	return setSockoptInt(fd, level, opt, val)
}

// FormatSocatAddr matches classic env formatting (IPv6 in brackets).

func NetworkTCP(g *Global, s parse.Spec, def string) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		if n := NetworkFromPF(pf, "tcp", ""); n != "" {
			return n
		}
	}
	ver := IPv4Default
	if g != nil {
		ver = g.IPVersion
	}
	switch ver {
	case IPv4:
		return "tcp4"
	case IPv6:
		return "tcp6"
	case IPvAny:
		return "tcp"
	default: // IPv4Default
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
