package xio

import (
	"context"
	"errors"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Linux AF_* values used in "opening connection to AF=N …" logs.
const (
	afINET  = 2  // AF_INET
	afINET6 = 10 // AF_INET6 on Linux (and most Unix)
)

// DialTarget is a TCP or SCTP connect destination.
type DialTarget struct {
	Network string // "tcp", "tcp4", "tcp6", or the SCTP equivalents
	Host    addrconfig.HostTarget
	Port    addrconfig.PortTarget
}

// DialTargetFromText builds a destination from leftover string hosts and ports.
func DialTargetFromText(network, host, port string) DialTarget {
	return DialTarget{Network: network, Host: addrconfig.HostFromText(host), Port: addrconfig.PortFromText(port)}
}

// dialCall is the shared context for one TCP connect attempt.
type dialCall struct {
	ctx     context.Context
	network string
	timeout time.Duration
	g       *Global
	control func(network, address string, c syscall.RawConn) error
}

func (c dialCall) withTimeout() (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return c.ctx, func() {}
	}
	return context.WithTimeout(c.ctx, c.timeout)
}

func (c dialCall) dialTCP(laddr, raddr *net.TCPAddr) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   c.timeout,
		LocalAddr: laddr,
		Control:   c.control,
	}
	d.SetMultipathTCP(false)
	cctx, cancel := c.withTimeout()
	defer cancel()
	return d.DialContext(cctx, c.network, formatTCPAddr(c.network, raddr.IP, raddr.Port))
}

// DialTCPAll resolves dest.Host and tries each address in order.
// dest.Network is "tcp", "tcp4", or "tcp6". Logs Notice "opening connection to AF=…"
// for each attempt.
func DialTCPAll(ctx context.Context, dest DialTarget, s addrconfig.Address, g *Global, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) (net.Conn, error) {
	host := StripBrackets(dest.Host.String())
	portNum, err := ResolvePort(dest.Network, dest.Port)
	if err != nil {
		return nil, err
	}
	ips, err := resolveDialIPs(ctx, dest, s, g)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	spText := SourcePortText(s)
	lowport := s.Network.LowPort.Value && (spText == "" || spText == "0")

	var lastErr error
	for _, ip := range ips {
		af := afForNetwork(dest.Network, ip)
		raddr := &net.TCPAddr{IP: ip, Port: portNum}
		if g != nil && g.Log != nil {
			// "opening connection to AF=2 127.0.0.1:9"
			g.Log.Noticef("opening connection to AF=%d %s", af, formatTCPAddr(dest.Network, ip, raddr.Port))
		}

		laddr, skip, err := BindTCPAddrForRemote(ctx, ip, s, dest.Network)
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

		netw := tcpDialNetwork(dest.Network, ip)
		call := dialCall{ctx: ctx, network: netw, timeout: timeout, g: g, control: DialControl(s, netw, control)}
		var c net.Conn
		if lowport {
			c, err = dialTCPLowport(call, raddr, laddr)
		} else {
			c, err = call.dialTCP(laddr, raddr)
		}
		if err != nil {
			lastErr = err
			if g != nil && g.Log != nil {
				// Notice for intermediate failures, Warning for last.
				g.Log.Noticef("connect AF=%d %s: %s", af, formatTCPAddr(netw, ip, raddr.Port), err)
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
		lastErr = fmt.Errorf("connect %s:%s failed", host, dest.Port.Text())
	}
	return nil, lastErr
}

func ResolveDialIPs(ctx context.Context, dest DialTarget, s addrconfig.Address, g *Global) ([]net.IP, error) {
	return resolveDialIPs(ctx, dest, s, g)
}

func resolveDialIPs(ctx context.Context, dest DialTarget, s addrconfig.Address, g *Global) ([]net.IP, error) {
	network := connectIPNetwork(dest.Network)
	host := StripBrackets(dest.Host.Original())
	if dest.Host.IsLiteral() {
		ip := dest.Host.IP()
		if ip == nil {
			return nil, fmt.Errorf("no addresses for %s", dest.Host.String())
		}
		if err := rejectConnectIPFamily(network, host, ip); err != nil {
			return nil, err
		}
		return []net.IP{ip}, nil
	}
	return resolveConnectIPs(ctx, network, host, s, g)
}

func connectIPNetwork(network string) string {
	switch network {
	case "sctp4":
		return "tcp4"
	case "sctp6":
		return "tcp6"
	case "sctp":
		return "tcp"
	default:
		return network
	}
}

func rejectConnectIPFamily(network, host string, ip net.IP) error {
	switch network {
	case "tcp4":
		if ip.To4() == nil {
			return fmt.Errorf("address %s: not IPv4", host)
		}
	case "tcp6":
		if ip.To4() != nil {
			return fmt.Errorf("address %s: not IPv6", host)
		}
	}
	return nil
}

// ResolvePort uses a prepared port. Numeric values are not looked up again.
func ResolvePort(network string, port addrconfig.PortTarget) (int, error) {
	if port.Numeric {
		return int(port.Number), nil
	}
	if port.Service == "" {
		return 0, fmt.Errorf("empty port")
	}
	return ResolvePortNum(network, port.Service)
}

// resolvePortNum accepts a numeric port or /etc/services name (TCP:host:http).
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
		// SCTP: try SCTP, then TCP names from /etc/services.
		if p, err := net.LookupPort("sctp", port); err == nil {
			return p, nil
		}
		return net.LookupPort("tcp", port)
	}
	return net.LookupPort(proto, port)
}

// ResolveConnectIPs returns remote IPs in try order.
// network may be tcp/tcp4/tcp6 or sctp/sctp4/sctp6 (SCTP uses the TCP hint).
func ResolveConnectIPs(ctx context.Context, network, host string, s addrconfig.Address, g *Global) ([]net.IP, error) {
	return resolveConnectIPs(ctx, connectIPNetwork(network), host, s, g)
}

func formatTCPAddr(network string, ip net.IP, port int) string {
	host := FormatIPForNetwork(network, ip)
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func tcpDialNetwork(network string, ip net.IP) string {
	return DialNetwork(network, ip)
}

func afForNetwork(network string, ip net.IP) int {
	if WantIPv4(network, ip) {
		return afINET
	}
	return afINET6
}

// resolveConnectIPs returns remote IPs in try order.
func resolveConnectIPs(ctx context.Context, network, host string, s addrconfig.Address, g *Global) ([]net.IP, error) {
	// Literal IP: single address, no DNS.
	if ip := net.ParseIP(host); ip != nil {
		if err := rejectConnectIPFamily(network, host, ip); err != nil {
			return nil, err
		}
		return []net.IP{ip}, nil
	}

	hint := IPHint(network)
	ips, err := LookupIP(ctx, s, hint, host)
	if err != nil {
		return nil, err
	}

	// Preference order for dual-stack ("tcp"): explicit ai-passive prefers
	// IPv6 when set, then -4/-6/-0, SOCAT_PREFERRED_RESOLVE_IP, then the
	// IPv4 default.
	if hint == "ip" && len(ips) > 1 {
		if s.Common.Passive.Value {
			sort.SliceStable(ips, func(i, j int) bool {
				return ips[i].To4() == nil && ips[j].To4() != nil
			})
		} else {
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

// localIPFamilies reports whether the host has a non-loopback, non-unspecified
// IPv4 and IPv6 address. Linux getaddrinfo(AI_ADDRCONFIG) ignores loopback
// (getaddrinfo(3)). Tests may replace it.
var localIPFamilies = localIPFamiliesFromSystem

func localIPFamiliesFromSystem() (v4, v6 bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true, true
	}
	return localIPFamiliesFromAddrs(addrs)
}

func localIPFamiliesFromAddrs(addrs []net.Addr) (v4, v6 bool) {
	for _, a := range addrs {
		var ip net.IP
		switch t := a.(type) {
		case *net.IPNet:
			ip = t.IP
		case *net.IPAddr:
			ip = t.IP
		}
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		if ip.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
		if v4 && v6 {
			return v4, v6
		}
	}
	return v4, v6
}

// BindTCPAddrForRemote picks a local TCPAddr matching remote's family.
// skip=true means try next remote.
func BindTCPAddrForRemote(ctx context.Context, remote net.IP, s addrconfig.Address, network string) (laddr *net.TCPAddr, skip bool, err error) {
	portTarget, hasPort := s.Network.LocalPort()
	if !s.Network.BindSet && (!hasPort || portTarget.Text() == "" || portTarget.Text() == "0") {
		return nil, false, nil
	}
	port := 0
	if hasPort && portTarget.Text() != "" && portTarget.Text() != "0" {
		port, err = ResolvePort("tcp", portTarget)
		if err != nil {
			return nil, false, fmt.Errorf("bind port: %w", err)
		}
	}
	want4 := WantIPv4(network, remote)

	if !s.Network.BindSet {
		// sourceport only: wildcard of matching family, or loopback when
		// ai-passive=0.
		if listenAIPassive(s) {
			if want4 {
				return &net.TCPAddr{IP: net.IPv4zero, Port: port}, false, nil
			}
			return &net.TCPAddr{IP: net.IPv6zero, Port: port}, false, nil
		}
		if want4 {
			return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, false, nil
		}
		return &net.TCPAddr{IP: net.IPv6loopback, Port: port}, false, nil
	}

	bind := s.Network.Bind
	if bind.IsLiteral() {
		ip := bind.IP()
		// Forced-IPv4 resolves bind= as AF_INET; an IPv6 wildcard
		// does not become 0.0.0.0. Skip this remote and try the next.
		if (ip.To4() != nil) != want4 {
			return nil, true, nil
		}
		return &net.TCPAddr{IP: ip, Port: port, Zone: bind.Literal.Zone()}, false, nil
	}

	bindHost := bind.String()
	hint := "ip6"
	if want4 {
		hint = "ip4"
	}
	ips, err := LookupIP(ctx, s, hint, bindHost)
	if err != nil {
		all, err2 := LookupIP(ctx, s, "ip", bindHost)
		if err2 != nil {
			return nil, false, fmt.Errorf("bind %s: %w", bind.Original(), err)
		}
		for _, ip := range all {
			if WantIPv4(network, ip) == want4 {
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

// dialTCPLowport binds a lowport (random start in 640-1023, walk down
// with wrap) then connects. Fail closed when no privileged port is
// available instead of falling back to an ephemeral port.
func dialTCPLowport(call dialCall, raddr, laddr *net.TCPAddr) (net.Conn, error) {
	ip := net.IPv4zero
	if raddr != nil && !WantIPv4(call.network, raddr.IP) {
		ip = net.IPv6zero
	}
	if laddr != nil && laddr.IP != nil {
		ip = laddr.IP
	}
	var conn net.Conn
	_, err := FirstAvailableLowport(func(port int) error {
		if call.g != nil && call.g.Log != nil {
			call.g.Log.Debugf("bind({AF=%d %s:%d}, 16)", afForNetwork(call.network, ip), FormatIPForNetwork(call.network, ip), port)
		}
		c, err := call.dialTCP(&net.TCPAddr{IP: ip, Port: port}, raddr)
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
func ConnectNetworkForType(g *Global, config addrconfig.Address, host, forced string) string {
	if config.Network.ProtocolSet {
		if n := networkFromIPFamily(config.Network.IPFamily, "tcp"); n != "" {
			return n
		}
	}
	if forced == "tcp4" || forced == "tcp6" {
		return forced
	}
	if n := networkFromIPFamily(config.Network.IPFamily, "tcp"); n != "" {
		return n
	}
	ht := config.Network.Target
	if !config.Network.TargetSet {
		ht = addrconfig.HostFromText(host)
	}
	if ht.IsLiteral() {
		if ht.Literal.Is4() {
			return "tcp4"
		}
		return "tcp6"
	}
	return "tcp"
}

// SingleUseDialer returns a DialContext that yields conn once. A second call
// returns reusedErr. The caller constructs reusedErr so WS and HTTP CONNECT
// can keep distinct messages.
func SingleUseDialer(conn net.Conn, reusedErr error) func(context.Context, string, string) (net.Conn, error) {
	var mu sync.Mutex
	return func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if conn == nil {
			if reusedErr != nil {
				return nil, reusedErr
			}
			return nil, errors.New("connection already used")
		}
		out := conn
		conn = nil
		return out, nil
	}
}
