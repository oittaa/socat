package addr

import (
	"context"
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

// dialTCPAll resolves host and tries each address in order (classic multi-A/AAAA).
// network is "tcp", "tcp4", or "tcp6". Logs Notice "opening connection to AF=…"
// for each attempt so TRY_ADDRS_* tests pass.
func dialTCPAll(ctx context.Context, network, host, port string, s parse.Spec, g *Global, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	host = stripBrackets(host)
	ips, err := resolveConnectIPs(ctx, network, host, s, g)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	bindOpt := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	if sp == "" {
		sp = "0"
	}

	var lastErr error
	for _, ip := range ips {
		af := afForIP(ip)
		raddr := &net.TCPAddr{IP: ip, Port: mustPort(port)}
		if g != nil && g.Log != nil {
			// Match classic: "opening connection to AF=2 127.0.0.1:9"
			g.Log.Noticef("opening connection to AF=%d %s", af, formatTCPAddr(ip, raddr.Port))
		}

		laddr, skip, err := bindTCPAddrForRemote(ctx, ip, bindOpt, sp, network)
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
		d := &net.Dialer{
			Timeout:   timeout,
			LocalAddr: laddr,
			Control:   control,
		}
		cctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			cctx, cancel = context.WithTimeout(ctx, timeout)
		}
		c, err := d.DialContext(cctx, netw, raddr.String())
		if cancel != nil {
			cancel()
		}
		if err != nil {
			lastErr = err
			if g != nil && g.Log != nil {
				// Classic uses Notice for intermediate failures, Warning for last.
				g.Log.Noticef("connect AF=%d %s: %s", af, formatTCPAddr(ip, raddr.Port), err)
			}
			continue
		}
		return c, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("connect %s:%s failed", host, port)
	}
	return nil, lastErr
}

func mustPort(port string) int {
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		// service names not resolved here; 0 lets dial fail clearly
		return 0
	}
	return n
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

	ips, err := net.DefaultResolver.LookupIP(ctx, hint, host)
	if err != nil {
		return nil, err
	}

	// ai-addrconfig: only keep families that have a configured local address.
	// Default off when option absent (Go resolver already reflects system policy).
	if s.HasOption("ai-addrconfig") && s.BoolOption("ai-addrconfig") {
		ips = filterAIAddrConfig(ips)
	}

	// Preference order for dual-stack ("tcp"): -6 → IPv6 first; -4/default → IPv4 first; -0 keep resolver order.
	if hint == "ip" && g != nil && len(ips) > 1 {
		switch g.IPVersion {
		case IPv6:
			sort.SliceStable(ips, func(i, j int) bool {
				return ips[i].To4() == nil && ips[j].To4() != nil
			})
		case IPv4, IPvDefault:
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

// bindTCPAddrForRemote picks a local TCPAddr matching remote's family.
// skip=true means no matching bind for this remote (try next remote).
func bindTCPAddrForRemote(ctx context.Context, remote net.IP, bindOpt, sourceport, network string) (laddr *net.TCPAddr, skip bool, err error) {
	if bindOpt == "" && (sourceport == "" || sourceport == "0") {
		return nil, false, nil
	}
	port := 0
	if sourceport != "" && sourceport != "0" {
		port, err = strconv.Atoi(sourceport)
		if err != nil {
			return nil, false, fmt.Errorf("sourceport: %w", err)
		}
	}
	want4 := remote.To4() != nil

	if bindOpt == "" {
		// sourceport only: wildcard of matching family
		if want4 {
			return &net.TCPAddr{IP: net.IPv4zero, Port: port}, false, nil
		}
		return &net.TCPAddr{IP: net.IPv6zero, Port: port}, false, nil
	}

	bindHost := stripBrackets(bindOpt)
	if ip := net.ParseIP(bindHost); ip != nil {
		if (ip.To4() != nil) != want4 {
			return nil, true, nil
		}
		return &net.TCPAddr{IP: ip, Port: port}, false, nil
	}

	// Hostname: resolve and pick first address matching remote family.
	hint := "ip"
	if want4 {
		hint = "ip4"
	} else {
		hint = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, hint, bindHost)
	if err != nil {
		// Fallback: full lookup then filter
		all, err2 := net.DefaultResolver.LookupIP(ctx, "ip", bindHost)
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

// connectNetworkForType picks dial network for a CONNECT address type.
// TCP4/TCP6 force a family; generic TCP uses dual-stack "tcp" (try both,
// ordered by -4/-6). pf= still forces a family.
func connectNetworkForType(g *Global, s parse.Spec, host, forced string) string {
	if forced == "tcp4" || forced == "tcp6" {
		// Still honour pf= override if present
		if pf := s.OptionValue("pf", ""); pf != "" {
			return networkFromPF(pf, forced)
		}
		return forced
	}
	if pf := s.OptionValue("pf", ""); pf != "" {
		return networkFromPF(pf, "tcp")
	}
	h := stripBrackets(host)
	if ip := net.ParseIP(h); ip != nil {
		if ip.To4() != nil {
			return "tcp4"
		}
		return "tcp6"
	}
	// Generic TCP: dual-stack resolve; -4/-6 only reorder.
	return "tcp"
}

func networkFromPF(pf, def string) string {
	switch strings.ToLower(pf) {
	case "ip4", "ipv4", "inet", "4":
		return "tcp4"
	case "ip6", "ipv6", "inet6", "6":
		return "tcp6"
	default:
		return def
	}
}
