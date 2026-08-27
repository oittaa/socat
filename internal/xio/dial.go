package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// Linux AF_* values used in classic "opening connection to AF=N …" logs.
// test.sh greps these lines for multi-address connect coverage.
const (
	afINET  = 2  // AF_INET
	afINET6 = 10 // AF_INET6 on Linux (and most Unix)
)

// DialTCPAll resolves host and tries each address in order (classic multi-A/AAAA).
// network is "tcp", "tcp4", or "tcp6". Logs Notice "opening connection to AF=…"
// for each attempt so TRY_ADDRS_* tests pass.
// port may be numeric or a /etc/services name (TCP4SERVICE).
func DialTCPAll(ctx context.Context, network, host, port string, s parse.Spec, g *Global, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	host = StripBrackets(host)
	portNum, err := ResolvePortNum(network, port)
	if err != nil {
		return nil, err
	}
	ips, err := resolveConnectIPs(ctx, network, host, s, g)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	bindOpt := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	lowport := s.BoolOption("lowport") && (sp == "" || sp == "0")

	var lastErr error
	for _, ip := range ips {
		af := afForIP(ip)
		raddr := &net.TCPAddr{IP: ip, Port: portNum}
		if g != nil && g.Log != nil {
			// Match classic: "opening connection to AF=2 127.0.0.1:9"
			g.Log.Noticef("opening connection to AF=%d %s", af, formatTCPAddr(ip, raddr.Port))
		}

		laddr, skip, err := BindTCPAddrForRemote(ctx, ip, s, bindOpt, sp)
		if err != nil {
			lastErr = err
			if g != nil && g.Log != nil {
				g.Log.Warningf("bind: %s", err)
			}
			continue
		}
		if skip {
			lastErr = fmt.Errorf("no bind address with matching address family (%d)", af)
			if g != nil && g.Log != nil {
				g.Log.Warningf("%s", lastErr)
			}
			continue
		}

		netw := "tcp4"
		if ip.To4() == nil {
			netw = "tcp6"
		}
		controlFn := DialControl(s, netw, control)
		var c net.Conn
		if lowport {
			c, err = dialTCPLowport(ctx, netw, raddr, laddr, timeout, controlFn, g)
		} else {
			d := &net.Dialer{
				Timeout:   timeout,
				LocalAddr: laddr,
				Control:   controlFn,
			}
			d.SetMultipathTCP(false)
			cctx := ctx
			var cancel context.CancelFunc
			if timeout > 0 {
				cctx, cancel = context.WithTimeout(ctx, timeout)
			}
			c, err = d.DialContext(cctx, netw, raddr.String())
			if cancel != nil {
				cancel()
			}
		}
		if err != nil {
			lastErr = err
			if g != nil && g.Log != nil {
				// Classic uses Notice for intermediate failures, Warning for last.
				g.Log.Noticef("connect AF=%d %s: %s", af, formatTCPAddr(ip, raddr.Port), err)
			}
			continue
		}
		if err := ApplyTCPConnOpts(s, c); err != nil {
			_ = c.Close()
			lastErr = err
			continue
		}
		return c, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("connect %s:%s failed", host, port)
	}
	return nil, lastErr
}

// resolvePortNum accepts a numeric port or /etc/services name (classic TCP:host:http).
func ResolvePortNum(network, port string) (int, error) {
	if port == "" {
		return 0, fmt.Errorf("empty port")
	}
	if n, err := strconv.Atoi(port); err == nil {
		if n < 0 || n > 65535 {
			return 0, fmt.Errorf("invalid port %s", port)
		}
		return n, nil
	}
	proto := "tcp"
	switch {
	case strings.HasPrefix(network, "udp"):
		proto = "udp"
	case strings.HasPrefix(network, "sctp"):
		// Classic SCTP_SERVICENAME: try SCTP, then TCP names from /etc/services.
		if p, err := net.LookupPort("sctp", port); err == nil {
			return p, nil
		}
		return net.LookupPort("tcp", port)
	}
	return net.LookupPort(proto, port)
}

// ResolveConnectIPs returns remote IPs in classic try order.
// network may be tcp/tcp4/tcp6 or sctp/sctp4/sctp6 (SCTP uses the TCP hint).
func ResolveConnectIPs(ctx context.Context, network, host string, s parse.Spec, g *Global) ([]net.IP, error) {
	switch network {
	case "sctp4":
		network = "tcp4"
	case "sctp6":
		network = "tcp6"
	case "sctp":
		network = "tcp"
	}
	return resolveConnectIPs(ctx, network, host, s, g)
}

func formatTCPAddr(ip net.IP, port int) string {
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

func afForIP(ip net.IP) int {
	if ip.To4() != nil {
		return afINET
	}
	return afINET6
}

// resolveConnectIPs returns remote IPs in classic try order.
func resolveConnectIPs(ctx context.Context, network, host string, s parse.Spec, g *Global) ([]net.IP, error) {
	// Literal IP: single address, no DNS.
	if ip := net.ParseIP(host); ip != nil {
		switch network {
		case "tcp4":
			if ip.To4() == nil {
				return nil, fmt.Errorf("address %s: not IPv4", host)
			}
		case "tcp6":
			if ip.To4() != nil {
				return nil, fmt.Errorf("address %s: not IPv6", host)
			}
		}
		return []net.IP{ip}, nil
	}

	hint := "ip"
	switch network {
	case "tcp4":
		hint = "ip4"
	case "tcp6":
		hint = "ip6"
	}

	ips, err := LookupResolver(s).LookupIP(ctx, hint, host)
	if err != nil {
		return nil, err
	}

	// ai-addrconfig: only keep families that have a configured local address.
	// Default off when option absent (Go resolver already reflects system policy).
	if s.HasOption("ai-addrconfig") && s.BoolOption("ai-addrconfig") {
		ips = filterAIAddrConfig(ips)
	}

	// Preference order for dual-stack ("tcp"): explicit -4/-6/-0, then
	// SOCAT_PREFERRED_RESOLVE_IP, then the IPv4 build default.
	if hint == "ip" && len(ips) > 1 {
		switch preferredResolveVersion(g) {
		case IPv6:
			sort.SliceStable(ips, func(i, j int) bool {
				return ips[i].To4() == nil && ips[j].To4() != nil
			})
		case IPv4, IPv4Default:
			sort.SliceStable(ips, func(i, j int) bool {
				return ips[i].To4() != nil && ips[j].To4() == nil
			})
		}
	}
	return ips, nil
}

func filterAIAddrConfig(ips []net.IP) []net.IP {
	have4, have6 := localIPFamilies()
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			if have4 {
				out = append(out, ip)
			}
		} else if have6 {
			out = append(out, ip)
		}
	}
	return out
}

func localIPFamilies() (v4, v6 bool) {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return true, true
	}
	for _, a := range ifaces {
		var ip net.IP
		switch t := a.(type) {
		case *net.IPNet:
			ip = t.IP
		case *net.IPAddr:
			ip = t.IP
		}
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		if ip.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
	}
	return v4, v6
}

// BindTCPAddrForRemote picks a local TCPAddr matching remote's family.
// bindOpt may be host, [ipv6], or host:port / [ipv6]:port (classic bind=).
// sourceport is used when bind has no port. skip=true means try next remote.
func BindTCPAddrForRemote(ctx context.Context, remote net.IP, s parse.Spec, bindOpt, sourceport string) (laddr *net.TCPAddr, skip bool, err error) {
	if bindOpt == "" && (sourceport == "" || sourceport == "0") {
		return nil, false, nil
	}
	bindHost, BindPort := "", "0"
	if sourceport != "" {
		BindPort = sourceport
	}
	if bindOpt != "" {
		// Prefer SplitHostPort so bind=127.0.0.1:0 and bind=[::1]:123 work.
		if h, p, e := net.SplitHostPort(bindOpt); e == nil {
			bindHost, BindPort = h, p
		} else {
			bindHost = StripBrackets(bindOpt)
		}
	}
	port := 0
	if BindPort != "" && BindPort != "0" {
		port, err = ResolvePortNum("tcp", BindPort)
		if err != nil {
			return nil, false, fmt.Errorf("bind port: %w", err)
		}
	} else if BindPort == "0" || BindPort == "" {
		port = 0
	}
	want4 := remote.To4() != nil

	if bindHost == "" {
		// sourceport only: wildcard of matching family
		if want4 {
			return &net.TCPAddr{IP: net.IPv4zero, Port: port}, false, nil
		}
		return &net.TCPAddr{IP: net.IPv6zero, Port: port}, false, nil
	}

	bindHost = StripBrackets(bindHost)
	if ip := net.ParseIP(bindHost); ip != nil {
		// Classic forced-IPv4 resolves bind= as AF_INET; an IPv6 wildcard
		// does not become 0.0.0.0. Skip this remote and try the next.
		if (ip.To4() != nil) != want4 {
			return nil, true, nil
		}
		return &net.TCPAddr{IP: ip, Port: port}, false, nil
	}

	// Hostname: resolve and pick first address matching remote family.
	hint := "ip6"
	if want4 {
		hint = "ip4"
	}
	ips, err := LookupResolver(s).LookupIP(ctx, hint, bindHost)
	if err != nil {
		// Fallback: full lookup then filter
		all, err2 := LookupResolver(s).LookupIP(ctx, "ip", bindHost)
		if err2 != nil {
			return nil, false, fmt.Errorf("bind %s: %w", bindOpt, err)
		}
		for _, ip := range all {
			if (ip.To4() != nil) == want4 {
				return &net.TCPAddr{IP: ip, Port: port}, false, nil
			}
		}
		return nil, true, nil
	}
	if len(ips) == 0 {
		return nil, true, nil
	}
	return &net.TCPAddr{IP: ips[0], Port: port}, false, nil
}

// dialTCPLowport binds a classic lowport (random start in 640-1023, walk down
// with wrap) then connects. Classic fails closed when no privileged port is
// available instead of falling back to an ephemeral port.
func dialTCPLowport(ctx context.Context, network string, raddr, laddr *net.TCPAddr, timeout time.Duration, control func(network, address string, c syscall.RawConn) error, g *Global) (net.Conn, error) {
	ip := net.IPv4zero
	if raddr != nil && raddr.IP.To4() == nil {
		ip = net.IPv6zero
	}
	if laddr != nil && laddr.IP != nil {
		ip = laddr.IP
	}
	var conn net.Conn
	_, err := FirstAvailableLowport(func(port int) error {
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind({AF=%d %s:%d}, 16)", afForIP(ip), ip.String(), port)
		}
		d := &net.Dialer{
			Timeout:   timeout,
			LocalAddr: &net.TCPAddr{IP: ip, Port: port},
			Control:   control,
		}
		d.SetMultipathTCP(false)
		cctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			cctx, cancel = context.WithTimeout(ctx, timeout)
		}
		c, err := d.DialContext(cctx, network, raddr.String())
		if cancel != nil {
			cancel()
		}
		if err != nil {
			return err
		}
		conn = c
		return nil
	})
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EADDRINUSE) {
			return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", LowportMin, LowportMax, err)
		}
		// The bind succeeded and connect failed (for example ECONNREFUSED).
		// Retrying every privileged port would hide the actual connect error.
		return nil, err
	}
	return conn, nil
}

// ConnectNetworkForType picks dial network for a CONNECT address type.
// TCP4/TCP6 force a family; generic TCP uses dual-stack "tcp" (try both,
// ordered by -4/-6). pf= still forces a family.
func ConnectNetworkForType(g *Global, s parse.Spec, host, forced string) string {
	if forced == "tcp4" || forced == "tcp6" {
		// Still honour pf= override if present
		if pf := s.OptionValue("pf", ""); pf != "" {
			return NetworkFromPF(pf, "tcp", forced)
		}
		return forced
	}
	if pf := s.OptionValue("pf", ""); pf != "" {
		return NetworkFromPF(pf, "tcp", "tcp")
	}
	h := StripBrackets(host)
	if ip := net.ParseIP(h); ip != nil {
		if ip.To4() != nil {
			return "tcp4"
		}
		return "tcp6"
	}
	// Generic TCP: dual-stack resolve; -4/-6 only reorder.
	return "tcp"
}
