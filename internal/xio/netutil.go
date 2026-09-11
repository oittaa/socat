package xio

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
)

// Lowport bind range: 640 through 1023.
const (
	LowportMin = 640
	LowportMax = 1023
)

// FirstAvailableLowport selects a random start in [LowportMin, LowportMax],
// then walks downward, wrapping from LowportMin to LowportMax, and stops
// after one full pass. Only EADDRINUSE advances to another port; permission
// and configuration errors fail immediately instead of being hidden by retries.
func FirstAvailableLowport(bind func(int) error) (int, error) {
	return firstAvailableLowportFrom(randomLowport(), bind)
}

func randomLowport() int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(LowportMax-LowportMin+1)))
	if err != nil {
		return LowportMax
	}
	return LowportMin + int(n.Int64())
}

// firstAvailableLowportFrom is the deterministic walk used by tests so they
// do not depend on the random start FirstAvailableLowport chooses.
func firstAvailableLowportFrom(start int, bind func(int) error) (int, error) {
	if start < LowportMin || start > LowportMax {
		start = LowportMax
	}
	var lastErr error
	port := start
	for range LowportMax - LowportMin + 1 {
		err := bind(port)
		if err == nil {
			return port, nil
		}
		lastErr = err
		if !errors.Is(err, syscall.EADDRINUSE) {
			return 0, err
		}
		port--
		if port < LowportMin {
			port = LowportMax
		}
	}
	if lastErr == nil {
		lastErr = syscall.EADDRINUSE
	}
	return 0, lastErr
}

// reuseaddrListenDefault is the SO_REUSEADDR default before bind.
// TCP listen turns it on. UDP-LISTEN (including UDP-L / UDP4-L / UDP6-L)
// sets it when fork is on. Other UDP-backed addresses (UDP-RECVFROM,
// QUIC-LISTEN, …) only set it when reuseaddr is present.
func reuseaddrListenDefault(s addrconfig.Address, network string) bool {
	if udpListenAddress(s.Type) {
		return ForkRequested(s)
	}
	switch network {
	case "udp", "udp4", "udp6":
		return false
	default:
		return true
	}
}

// udpListenAddress reports whether addrType is a UDP listen keyword
// (including UDP-L / UDP4-L / UDP6-L). QUIC-LISTEN is not UDP-LISTEN.
func udpListenAddress(addrType string) bool {
	if reg, ok := AddressRegistrationForType(addrType); ok {
		addrType = reg.Name
	}
	switch strings.ToUpper(strings.TrimSpace(addrType)) {
	case "UDP-LISTEN", "UDP-L", "UDP4-LISTEN", "UDP4-L", "UDP6-LISTEN", "UDP6-L":
		return true
	default:
		return false
	}
}

// UDPForkPortReuse reports whether a UDP-LISTEN fork session may share the
// parent's port (SO_REUSEPORT on macOS; SO_REUSEADDR on connected child sockets).
// A connected child needs equivalent port reuse so it can bind the same local
// port while the parent stays listening. Explicit reuseaddr=0 disables
// sharing; the first session then takes the listen socket instead of dropping
// the datagram.
func UDPForkPortReuse(s addrconfig.Address) bool {
	if !udpListenAddress(s.Type) || !ForkRequested(s) {
		return false
	}
	if s.Network.ReuseAddr.Set {
		return s.Network.ReuseAddr.Value
	}
	return true
}

// ApplyReuse sets SO_REUSEADDR and optional SO_REUSEPORT on fd.
// reuseaddrDefault is used when reuseaddr is not present on the spec.
func ApplyReuse(fd int, s addrconfig.Address, reuseaddrDefault bool) error {
	reuse := reuseaddrDefault
	if s.Network.ReuseAddr.Set {
		reuse = s.Network.ReuseAddr.Value
	}
	if reuse {
		if err := setSockoptInt(fd, solSocket, soReuseaddr, 1); err != nil && s.Network.ReuseAddr.Set {
			return fmt.Errorf("reuseaddr: %w", err)
		}
	}
	if s.Network.ReusePort.Value {
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
func ApplyReuseAndV6Only(fd int, s addrconfig.Address, network string) error {
	if err := ApplyReuse(fd, s, reuseaddrListenDefault(s, network)); err != nil {
		return err
	}
	switch network {
	case "tcp", "tcp6", "udp", "udp6":
	default:
		return nil
	}
	if s.Common.IPv6V6Only.Set {
		v := 0
		if s.Common.IPv6V6Only.Value {
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

// ApplyListenOptions applies socket options that must be set before bind
// (reuseaddr/reuseport/ipv6-v6only plus setsockopt-listen).
// so-broadcast and other post-socket options live in ApplySocketOptions and
// must run first (DialControl / ListenControl / listenUDP Control).
func ApplyListenOptions(fd int, s addrconfig.Address, network string) error {
	// Windows AF_UNIX sockets reject SO_REUSEADDR and can remain unusable
	// after the failed call. UNIX path reuse is handled by the opener instead.
	if !strings.HasPrefix(network, "unix") {
		if err := ApplyReuseAndV6Only(fd, s, network); err != nil {
			return err
		}
	}
	return ApplyPrebindPhase(fd, s)
}

// ApplyPastSocketPhase applies post-socket options immediately after
// socket(): SOL_SOCKET buffers/broadcast/bindtodevice/so-debug plus named TCP
// (tcp-cork, tcp-maxseg, …) and Linux SCTP (sctp-nodelay, sctp-maxseg),
// setsockopt-socket, and ip-ttl/tos on TCP/SCTP.
func ApplyPastSocketPhase(fd int, s addrconfig.Address, network string) error {
	noteOptionPhase("PASTSOCKET")
	return ApplyNetworkSocketOptions(fd, s, network)
}

// ApplyPrebindPhase applies generic setsockopt-listen and ip-transparent
// before bind()/connect(), in command-line order.
func ApplyPrebindPhase(fd int, s addrconfig.Address) error {
	return applyPreparedSocketPhase(fd, s, socketApplyPrebind, "")
}

// ApplyPastSocketThenPrebind is the Control-hook order used by net.Dialer
// and net.ListenConfig: ApplyPastSocketPhase after socket(), then
// ApplyPrebindPhase, then return so connect()/bind() happens after both.
func ApplyPastSocketThenPrebind(fd int, s addrconfig.Address, network string) error {
	if err := ApplyPastSocketPhase(fd, s, network); err != nil {
		return err
	}
	return ApplyPrebindPhase(fd, s)
}

// ListenControl is a net.ListenConfig.Control that applies
// ApplyPastSocketPhase then ApplyListenOptions before bind().
func ListenControl(s addrconfig.Address) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var optionErr error
		controlErr := c.Control(func(fd uintptr) {
			optionErr = ApplyPastSocketPhase(int(fd), s, network)
			if optionErr == nil {
				optionErr = ApplyListenOptions(int(fd), s, network)
			}
		})
		return errors.Join(controlErr, optionErr)
	}
}

// NewTCPListenConfig is ListenConfig for TCP/TLS/WS listen.
// Go 1.21+ may create IPPROTO_MPTCP sockets by default; TCP-LISTEN is
// IPPROTO_TCP. MPTCP silently no-ops SO_DONTROUTE (setsockopt succeeds,
// getsockopt stays 0) and rejects TCP_MAXSEG (ENOPROTOOPT), so named
// post-socket options would not have kernel effect. Stay on TCP.
func NewTCPListenConfig(s addrconfig.Address) net.ListenConfig {
	lc := net.ListenConfig{Control: ListenControl(s)}
	lc.SetMultipathTCP(false)
	return lc
}

// ApplyNetworkSocketOptions applies the post-socket options shared by Go net
// listeners/dialers and raw SCTP sockets. Fixed SOL_SOCKET, named
// SOL_SOCKET/TCP/SCTP, generic setsockopt-socket, and IP/ancillary/membership
// options are applied once in command-line order before bind/connect.
func ApplyNetworkSocketOptions(fd int, s addrconfig.Address, network string) error {
	return applyPreparedSocketPhase(fd, s, socketApplyPastSocket, network)
}

// DialControl merges spec-driven socket options with an optional
// caller-provided Control. Go's Control hook runs after socket() and before
// connect(), so both post-socket and pre-bind phases go here.
func DialControl(s addrconfig.Address, network string, caller func(string, string, syscall.RawConn) error) func(string, string, syscall.RawConn) error {
	return func(nw, addr string, c syscall.RawConn) error {
		optionNetwork := network
		if optionNetwork == "" {
			optionNetwork = nw
		}
		var optErr error
		controlErr := c.Control(func(fd uintptr) {
			optErr = ApplyPastSocketThenPrebind(int(fd), s, optionNetwork)
		})
		if err := errors.Join(controlErr, optErr); err != nil {
			return err
		}
		if caller != nil {
			return caller(nw, addr, c)
		}
		return nil
	}
}

func forcedIPv4Network(network string) bool {
	switch network {
	case "tcp4", "udp4", "ip4", "sctp4":
		return true
	default:
		return false
	}
}

func forcedIPv6Network(network string) bool {
	switch network {
	case "tcp6", "udp6", "ip6", "sctp6":
		return true
	default:
		return false
	}
}

func listenAIPassive(config addrconfig.Address) bool {
	if config.Common.Passive.Set {
		return config.Common.Passive.Value
	}
	return true
}

// BindHost is the prepared bind= value, or empty when the option is absent.
func BindHost(config addrconfig.Address) string {
	if !config.Network.BindSet {
		return ""
	}
	if config.Network.Bind.Name != "" {
		return config.Network.Bind.Name
	}
	return config.Network.Bind.String()
}

// SourcePortText is the prepared sourceport= value, or empty when absent.
func SourcePortText(config addrconfig.Address) string {
	if !config.Network.SourcePortSet {
		return ""
	}
	return config.Network.SourcePort.Text()
}

// ProtocolFamilyText is the prepared pf= token, or empty when absent.
func ProtocolFamilyText(config addrconfig.Address) string {
	return config.Network.ProtocolFamilyToken()
}

// DualStackListenNetwork maps *6 networks onto dual-stack names when
// ipv6-v6only=0. Other values keep the caller network.
func DualStackListenNetwork(config addrconfig.Address, network string) string {
	if !config.Common.IPv6V6Only.Set || config.Common.IPv6V6Only.Value {
		return network
	}
	switch network {
	case "tcp6":
		return "tcp"
	case "udp6":
		return "udp"
	case "sctp6":
		return "sctp"
	default:
		return network
	}
}

// ListenBindHost resolves the bind host for listen and local-bind paths.
// An explicit bind= value is returned unchanged: never rewrite :: to 0.0.0.0.
// A family wildcard is supplied only when bind is absent.
// Forced-family combinations that would otherwise fail inside the OS resolver
// (TCP4/UDP4 vs ::, TCP6 vs 0.0.0.0) return a clear error.
//
// LISTEN/RECV/bind set getaddrinfo AI_PASSIVE unless ai-passive=0.
// AI_PASSIVE with an empty node is the wildcard; unset is loopback.
func ListenBindHost(s addrconfig.Address, network, bind string) (string, error) {
	if bind == "" {
		bind = BindHost(s)
	}
	if bind == "" {
		if listenAIPassive(s) {
			if forcedIPv4Network(network) {
				return "0.0.0.0", nil
			}
			return "::", nil
		}
		if forcedIPv4Network(network) {
			return "127.0.0.1", nil
		}
		return "::1", nil
	}
	host := StripBrackets(bind)
	if h, _, err := net.SplitHostPort(bind); err == nil {
		host = StripBrackets(h)
	}
	if ip := net.ParseIP(host); ip != nil {
		is4 := ip.To4() != nil
		if forcedIPv4Network(network) && !is4 {
			return "", fmt.Errorf("bind: address family mismatch (%s on %s)", bind, network)
		}
		if forcedIPv6Network(network) && is4 {
			return "", fmt.Errorf("bind: address family mismatch (%s on %s)", bind, network)
		}
	}
	return bind, nil
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

func HostPortParams(s addrconfig.Address) (host, port string, err error) {
	if !s.Network.TargetSet {
		return "", "", fmt.Errorf("%s requires host and port", s.Type)
	}
	host, port = s.Network.Target.String(), s.Network.TargetPort.Text()
	if host == "" || port == "" {
		return "", "", fmt.Errorf("%s: invalid host/port", s.Type)
	}
	return host, port, nil
}

func ListenPortText(s addrconfig.Address) (string, error) {
	if !s.Network.ListenSet {
		return "", fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Network.ListenPort.Text()
	if port == "" || strings.Trim(port, ":") == "" {
		return "", fmt.Errorf("%s: invalid port %q", s.Type, port)
	}
	return port, nil
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

func ConnectTimeout(config addrconfig.Address) time.Duration {
	if config.Common.ConnectTimeout.Set {
		return config.Common.ConnectTimeout.Value
	}
	return 0
}

// pfVersion maps pf= names (and PF_* numbers) to a family.
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

// TCPToUDPNetwork maps a TCP network name onto the corresponding UDP name.
// tcp4/tcp6 become udp4/udp6; tcp, empty, and unknown names become udp.
func TCPToUDPNetwork(tcpNet string) string {
	switch strings.ToLower(tcpNet) {
	case "tcp4":
		return "udp4"
	case "tcp6":
		return "udp6"
	default:
		return "udp"
	}
}

func ListenNetwork(g *Global, config addrconfig.Address) string {
	if n := NetworkFromPF(ProtocolFamilyText(config), "tcp", ""); n != "" {
		return n
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

func AcceptTimeout(config addrconfig.Address) time.Duration {
	if config.Common.AcceptTimeout.Set {
		return config.Common.AcceptTimeout.Value
	}
	return 0
}

func IsTimeoutErr(err error) bool {
	// Broader than net.Error: any wrapped Timeout() bool is a timeout.
	// Child packages keep calling this helper so they do not import relay.
	return relay.IsTimeoutErr(err)
}

// applyKeepAliveConfig builds net.KeepAliveConfig from the keepalive
// family: keepalive toggle, keepidle/keepintvl/keepcnt values.
// Any sub-option implies enable; an explicit keepalive=0 disables even when
// sub-options are present. Unset fields keep their platform defaults.
func applyKeepAliveConfig(config addrconfig.Address, tc *net.TCPConn) error {
	n := config.Network
	if !n.KeepAlive.Set && !n.KeepIdle.Set && !n.KeepIntvl.Set && !n.KeepCnt.Set {
		return nil
	}
	enable := true
	if n.KeepAlive.Set {
		enable = n.KeepAlive.Value
	}
	// Negative values preserve the current OS settings. Zero would replace
	// omitted fields with Go's defaults (15s/15s/9), which is not what a
	// single tcp-keep* option requests.
	cfg := net.KeepAliveConfig{
		Enable:   enable,
		Idle:     -1,
		Interval: -1,
		Count:    -1,
	}
	if n.KeepIdle.Set {
		cfg.Idle = n.KeepIdle.Value
	}
	if n.KeepIntvl.Set {
		cfg.Interval = n.KeepIntvl.Value
	}
	if n.KeepCnt.Set {
		cfg.Count = n.KeepCnt.Value
	}
	if err := tc.SetKeepAliveConfig(cfg); err != nil {
		return fmt.Errorf("keepalive: %w", err)
	}
	return nil
}

// ApplyTCPConnOpts applies TCP keepalive/nodelay plus post-connect generic
// setsockopt and named tcp-maxseg-late on the unwrapped raw conn.
// IP TTL/TOS, so-debug/tcp-cork, and other post-socket options were already
// applied by DialControl/ListenControl. SETSOCKOPT uses
// setsockopt=6:TCP_MAXSEG:512 (IPPROTO_TCP + TCP_MAXSEG) after connect.
// Non-TCP connections that expose a socket fd still get generic setsockopt
// and named connected TCP opts; a present option is never ignored because
// the conn is not *net.TCPConn (TCP_* on UDP/SCTP fails clearly).
func ApplyTCPConnOpts(s addrconfig.Address, c net.Conn) error {
	noteOptionPhase("CONNECTED")
	c = unwrapNetConn(c)
	if tc, ok := c.(*net.TCPConn); ok {
		if err := applyKeepAliveConfig(s, tc); err != nil {
			return err
		}
		if s.Network.NoDelay.Set {
			if err := tc.SetNoDelay(s.Network.NoDelay.Value); err != nil {
				return fmt.Errorf("nodelay: %w", err)
			}
		}
		if err := ApplyGenericSetsockoptToNetConn(tc, s, SockoptPhaseConnected); err != nil {
			return err
		}
		// so-sndbuf-late / so-rcvbuf-late on the raw TCP fd after
		// connect()/accept(), before TLS/PROXY handshake. WrapOpened
		// still applies the same options on UNIX/UDP streams; a second
		// SO_SNDBUF set on this TCP conn is harmless.
		return ApplyLateSocketOptionsToConn(tc, s)
	}
	return ApplyGenericSetsockoptToNetConn(c, s, SockoptPhaseConnected)
}

func FirstHost(s addrconfig.Address) string {
	if s.Network.TargetSet {
		return s.Network.Target.String()
	}
	if len(s.Params) > 0 {
		return s.Params[0]
	}
	return ""
}

// RecvTimeout returns the prepared so-rcvtimeo / rcvtimeo duration.
// An omitted value means unlimited.
func RecvTimeout(config addrconfig.Address) (time.Duration, error) {
	if config.Common.ReadTimeout.Set {
		return config.Common.ReadTimeout.Value, nil
	}
	return 0, nil
}

// RecvOneCtx performs one datagram read through read in a goroutine so that
// context cancellation returns promptly even though the underlying socket has
// no deadline. The abandoned read completes into a buffered channel and is
// released when the caller closes the socket.
func RecvOneCtx[A any](ctx context.Context, read func() (int, []byte, A, error)) (int, []byte, A, error) {
	type result struct {
		n    int
		oob  []byte
		addr A
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		n, oob, addr, err := read()
		ch <- result{n: n, oob: oob, addr: addr, err: err}
	}()
	select {
	case <-ctx.Done():
		var zero A
		return 0, nil, zero, ctx.Err()
	case r := <-ch:
		return r.n, r.oob, r.addr, r.err
	}
}
