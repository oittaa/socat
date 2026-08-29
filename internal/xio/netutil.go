package xio

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
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
func reuseaddrListenDefault(s parse.Spec, network string) bool {
	if udpListenAddress(s.Type) {
		return s.BoolOption("fork")
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
func UDPForkPortReuse(s parse.Spec) bool {
	if !udpListenAddress(s.Type) || !s.BoolOption("fork") {
		return false
	}
	if s.HasOption("reuseaddr") {
		return s.BoolOption("reuseaddr")
	}
	return true
}

// ApplyReuse sets SO_REUSEADDR and optional SO_REUSEPORT on fd.
// reuseaddrDefault is used when reuseaddr is not present on the spec.
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
	if err := ApplyReuse(fd, s, reuseaddrListenDefault(s, network)); err != nil {
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

// ApplyListenOptions applies socket options that must be set before bind
// (reuseaddr/reuseport/ipv6-v6only plus setsockopt-listen).
// so-broadcast and other post-socket options live in ApplySocketOptions and
// must run first (DialControl / ListenControl / listenUDP Control).
func ApplyListenOptions(fd int, s parse.Spec, network string) error {
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
func ApplyPastSocketPhase(fd int, s parse.Spec, network string) error {
	noteOptionPhase("PASTSOCKET")
	return ApplyNetworkSocketOptions(fd, s, network)
}

// ApplyPrebindPhase applies generic setsockopt-listen and ip-transparent
// before bind()/connect(), in command-line order.
func ApplyPrebindPhase(fd int, s parse.Spec) error {
	for _, o := range s.Options {
		if kind, ok := genericSetsockoptKind(o.Name, SockoptPhasePrebind); ok {
			if err := applyGenericSetsockoptOption(fd, o, kind); err != nil {
				return err
			}
			continue
		}
		if matched, err := applyTransparentOption(fd, o); matched {
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyPastSocketThenPrebind is the Control-hook order used by net.Dialer
// and net.ListenConfig: ApplyPastSocketPhase after socket(), then
// ApplyPrebindPhase, then return so connect()/bind() happens after both.
func ApplyPastSocketThenPrebind(fd int, s parse.Spec, network string) error {
	if err := ApplyPastSocketPhase(fd, s, network); err != nil {
		return err
	}
	return ApplyPrebindPhase(fd, s)
}

// ListenControl is a net.ListenConfig.Control that applies
// ApplyPastSocketPhase then ApplyListenOptions before bind().
func ListenControl(s parse.Spec) func(network, address string, c syscall.RawConn) error {
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
func NewTCPListenConfig(s parse.Spec) net.ListenConfig {
	lc := net.ListenConfig{Control: ListenControl(s)}
	lc.SetMultipathTCP(false)
	return lc
}

// ApplyNetworkSocketOptions applies the post-socket options shared by Go net
// listeners/dialers and raw SCTP sockets. Fixed SOL_SOCKET, named
// SOL_SOCKET/TCP/SCTP, generic setsockopt-socket, and IP/ancillary/membership
// options are applied once in command-line order before bind/connect.
func ApplyNetworkSocketOptions(fd int, s parse.Spec, network string) error {
	if err := ApplySocketOptionsWithoutGeneric(fd, s); err != nil {
		return err
	}
	return applyOrderedPastSocketPhaseOptions(fd, s, network)
}

// ApplyListenBacklog updates the pending-connection queue of an existing TCP
// listener. Both POSIX and Winsock allow listen to be called again to change
// the backlog; using the existing listener preserves Go's platform-specific
// socket setup and dual-stack behavior.
func ApplyListenBacklog(ln net.Listener, backlog int) error {
	sc, ok := ln.(syscall.Conn)
	if !ok {
		return fmt.Errorf("listener does not expose its socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = setListenBacklog(int(fd), backlog)
	})
	return errors.Join(controlErr, optionErr)
}

// DialControl merges spec-driven socket options with an optional
// caller-provided Control. Go's Control hook runs after socket() and before
// connect(), so both post-socket and pre-bind phases go here.
func DialControl(s parse.Spec, network string, caller func(string, string, syscall.RawConn) error) func(string, string, syscall.RawConn) error {
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

func listenAIPassive(s parse.Spec) bool {
	if s.HasOption("ai-passive") {
		return s.BoolOption("ai-passive")
	}
	return true
}

// ListenBindHost resolves the bind host for listen and local-bind paths.
// An explicit bind= value is returned unchanged: never rewrite :: to 0.0.0.0.
// A family wildcard is supplied only when bind is absent.
// Forced-family combinations that would otherwise fail inside the OS resolver
// (TCP4/UDP4 vs ::, TCP6 vs 0.0.0.0) return a clear error.
//
// LISTEN/RECV/bind set getaddrinfo AI_PASSIVE unless ai-passive=0.
// AI_PASSIVE with an empty node is the wildcard; unset is loopback.
func ListenBindHost(s parse.Spec, network, bind string) (string, error) {
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

// applyKeepAliveConfig builds net.KeepAliveConfig from the keepalive
// family: keepalive/so-keepalive toggle, keepidle/keepintvl/keepcnt values.
// Any sub-option implies enable; an explicit keepalive=0 disables even when
// sub-options are present. Unset fields keep their platform defaults.
func applyKeepAliveConfig(s parse.Spec, tc *net.TCPConn) error {
	anyOpt := false
	enable := true
	for _, n := range []string{"keepalive", "so-keepalive", "keepidle", "keepintvl", "keepcnt"} {
		if s.HasOption(n) {
			anyOpt = true
			break
		}
	}
	if !anyOpt {
		return nil
	}
	if s.HasOption("keepalive") || s.HasOption("so-keepalive") {
		enable = s.BoolOption("keepalive") || s.BoolOption("so-keepalive")
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

	durFrom := func(o parse.Option) (time.Duration, error) {
		d, err := parseTimeval(o.Value)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", o.Name, err)
		}
		if d <= 0 {
			return 0, fmt.Errorf("%s: must be positive, got %q", o.Name, o.Value)
		}
		return d, nil
	}
	if o, ok := s.OptionNamed("keepidle"); ok && o.Has && strings.TrimSpace(o.Value) != "" {
		d, err := durFrom(o)
		if err != nil {
			return err
		}
		cfg.Idle = d
	}
	if o, ok := s.OptionNamed("keepintvl"); ok && o.Has && strings.TrimSpace(o.Value) != "" {
		d, err := durFrom(o)
		if err != nil {
			return err
		}
		cfg.Interval = d
	}
	if o, ok := s.OptionNamed("keepcnt"); ok && o.Has && strings.TrimSpace(o.Value) != "" {
		n, err := ParseIntAny(o.Value)
		if err != nil || n <= 0 {
			return fmt.Errorf("keepcnt: invalid count %q", o.Value)
		}
		cfg.Count = n
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
func ApplyTCPConnOpts(s parse.Spec, c net.Conn) error {
	noteOptionPhase("CONNECTED")
	c = unwrapNetConn(c)
	if tc, ok := c.(*net.TCPConn); ok {
		if err := applyKeepAliveConfig(s, tc); err != nil {
			return err
		}
		if s.HasOption("nodelay") || s.HasOption("tcp-nodelay") {
			enabled := s.BoolOption("nodelay") || s.BoolOption("tcp-nodelay")
			if err := tc.SetNoDelay(enabled); err != nil {
				return fmt.Errorf("nodelay: %w", err)
			}
		}
		if err := ApplyGenericSetsockoptToNetConn(tc, s, SockoptPhaseConnected); err != nil {
			return err
		}
		// so-sndbuf-late / so-rcvbuf-late on the raw TCP fd after
		// connect()/accept(), before TLS/PROXY handshake. WrapCommon
		// still applies the same options on UNIX/UDP streams; a second
		// SO_SNDBUF set on this TCP conn is harmless.
		return ApplyLateSocketOptionsToConn(tc, s)
	}
	return ApplyGenericSetsockoptToNetConn(c, s, SockoptPhaseConnected)
}

func ParsePositiveInt(v string) (int, error) {
	n, err := ParseIntAny(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid")
	}
	return n, nil
}

func ParseIntAny(v string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 0, 64)
	if err != nil {
		return 0, err
	}
	if n > math.MaxInt || n < math.MinInt {
		return 0, fmt.Errorf("out of range")
	}
	return int(n), nil
}

// ParseSizeT parses an unsigned size. An optional minus sign is converted
// modulo 2^64, so readbytes=-1 means the largest possible limit rather than
// a parse failure.
func ParseSizeT(v string) (uint64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("empty value")
	}
	negative := v[0] == '-'
	if negative || v[0] == '+' {
		v = v[1:]
		if v == "" {
			return 0, fmt.Errorf("invalid value")
		}
	}
	n, err := strconv.ParseUint(v, 0, 64)
	if err != nil {
		return 0, err
	}
	if negative {
		return -n, nil
	}
	return n, nil
}

func FirstHost(s parse.Spec) string {
	if len(s.Params) > 0 {
		return s.Params[0]
	}
	return ""
}

func parseTimeval(v string) (time.Duration, error) {
	// timeval: seconds with optional fractional part
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("empty timeout")
	}
	f, err := strconv.ParseFloat(v, 64)
	if err == nil {
		secondsLimit := float64(math.MaxInt64) / float64(time.Second)
		if math.IsNaN(f) || math.IsInf(f, 0) || f > secondsLimit || f < -secondsLimit {
			return 0, fmt.Errorf("timeout out of range")
		}
		return time.Duration(f * float64(time.Second)), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	return d, nil
}

func ParseTimeval(v string) time.Duration {
	d, _ := parseTimeval(v)
	return d
}

// RecvTimeoutFromSpec parses so-rcvtimeo / rcvtimeo. An empty value means
// unlimited; a present but invalid value is an error.
func RecvTimeoutFromSpec(s parse.Spec) (time.Duration, error) {
	v := s.OptionValue("rcvtimeo", "")
	if v == "" {
		return 0, nil
	}
	d, err := parseTimeval(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("rcvtimeo: invalid timeout %q", v)
	}
	return d, nil
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
