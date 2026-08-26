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

// Classic lowport bind range from xio-socket.c xiobind (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same): 640 through 1023.
const (
	LowportMin = 640
	LowportMax = 1023
)

// FirstAvailableLowport selects a random start in [LowportMin, LowportMax]
// (classic: 640 + random() % 384), then walks downward, wrapping from
// LowportMin to LowportMax, and stops after one full pass. Matching classic
// xiobind, only EADDRINUSE advances to another port; permission and
// configuration errors fail immediately instead of being hidden by retries.
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
// Classic xiosock_reuseaddr (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree) turns it on for
// TCP listen. Classic _xioopen_ipdgram_listen (UDP-LISTEN, UDP4-LISTEN, and
// UDP6-LISTEN, including aliases UDP-L, UDP4-L, UDP6-L) sets it when fork is
// on. Other UDP-backed addresses (UDP-RECVFROM, QUIC-LISTEN, …) only set it
// when reuseaddr is present. Classic 1.7.2.0 treated always-on UDP-LISTEN
// reuse as a bug.
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

// udpListenAddress reports whether addrType is classic UDP-LISTEN after
// addressnames[] alias expansion. Do not use GoAddressClassicAlias: QUIC-LISTEN
// maps to OPENSSL-DTLS-SERVER for option groups, not for this default.
func udpListenAddress(addrType string) bool {
	t := strings.ToUpper(strings.TrimSpace(addrType))
	if alias, ok := ClassicAddressAliases[t]; ok {
		t = alias
	}
	switch t {
	case "UDP-LISTEN", "UDP4-LISTEN", "UDP6-LISTEN":
		return true
	default:
		return false
	}
}

// UDPForkPortReuse reports whether a UDP-LISTEN fork session may share the
// parent's port (SO_REUSEPORT on BSD; SO_REUSEADDR on connected child sockets).
// Classic does not set SO_REUSEPORT; the Go port needs equivalent port reuse so
// a connected child can bind the same local port while the parent stays
// listening. Explicit reuseaddr=0 disables sharing; the first session then
// takes the listen socket (classic child inherits the fd) instead of dropping
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

// ApplyListenOptions applies socket options that must be set before bind.
func ApplyListenOptions(fd int, s parse.Spec, network string) error {
	// Classic so-broadcast is PH_PASTSOCKET (after socket, before PREBIND).
	// UDP ListenConfig.Control paths call this helper and not ApplySocketOptions
	// until after bind, so apply it here as well as in ApplySocketOptions.
	if err := applyBroadcast(fd, s); err != nil {
		return err
	}
	// Windows AF_UNIX sockets reject SO_REUSEADDR and can remain unusable
	// after the failed call. UNIX path reuse is handled by the opener instead.
	if !strings.HasPrefix(network, "unix") {
		if err := ApplyReuseAndV6Only(fd, s, network); err != nil {
			return err
		}
	}
	if s.HasOption("setsockopt-listen") {
		return ApplySetsockoptFD(fd, s.OptionValue("setsockopt-listen", ""))
	}
	return nil
}

// ListenControl is a net.ListenConfig.Control that applies pre-bind options.
func ListenControl(s parse.Spec) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var optionErr error
		controlErr := c.Control(func(fd uintptr) {
			optionErr = ApplyListenOptions(int(fd), s, network)
			if optionErr == nil {
				optionErr = ApplyNetworkSocketOptions(int(fd), s, network)
			}
		})
		return errors.Join(controlErr, optionErr)
	}
}

// ApplyNetworkSocketOptions applies the post-socket options shared by Go net
// listeners/dialers and raw SCTP sockets. Membership (PH_PASTSOCKET
// IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP) is applied here so DialControl and
// ListenControl cover UDP connect, TCP connect, and TCP listen. Classic
// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same option tree.
func ApplyNetworkSocketOptions(fd int, s parse.Spec, network string) error {
	if err := ApplySocketOptions(fd, s); err != nil {
		return err
	}
	if err := applyIPTTLTOS(fd, s, network); err != nil {
		return err
	}
	return ApplyMembershipJoins(fd, s)
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

// DialControl merges spec-driven socket options (rcvtimeo/sndtimeo, and
// ip-ttl/ip-tos on tcp networks) with an optional caller-provided Control,
// producing a single net.Dialer.Control.
func DialControl(s parse.Spec, network string, caller func(string, string, syscall.RawConn) error) func(string, string, syscall.RawConn) error {
	return func(nw, addr string, c syscall.RawConn) error {
		optionNetwork := network
		if optionNetwork == "" {
			optionNetwork = nw
		}
		var optErr error
		controlErr := c.Control(func(fd uintptr) {
			optErr = ApplyNetworkSocketOptions(int(fd), s, optionNetwork)
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

// ListenBindHost resolves the bind host for listen and local-bind paths.
// An explicit bind= value is returned unchanged: never rewrite :: to 0.0.0.0.
// A family wildcard is supplied only when bind is absent.
// Forced-family combinations that would otherwise fail inside the OS resolver
// (TCP4/UDP4 vs ::, TCP6 vs 0.0.0.0) return a clear error.
func ListenBindHost(network, bind string) (string, error) {
	if bind == "" {
		if forcedIPv4Network(network) {
			return "0.0.0.0", nil
		}
		return "::", nil
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

// applyKeepAliveConfig builds net.KeepAliveConfig from the classic keepalive
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
	// single classic tcp-keep* option requests.
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

// ApplyTCPConnOpts parses classic setsockopt=level:optname:value (ints) and applies it.
// SETSOCKOPT test uses setsockopt=6:TCP_MAXSEG:512 (IPPROTO_TCP + TCP_MAXSEG).
func ApplyTCPConnOpts(s parse.Spec, c net.Conn) error {
	for {
		unwrapper, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		inner := unwrapper.NetConn()
		if inner == nil || inner == c {
			break
		}
		c = inner
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil
	}
	if la, ok := tc.LocalAddr().(*net.TCPAddr); ok {
		network := "tcp6"
		if la.IP.To4() != nil {
			network = "tcp4"
		}
		if raw, rerr := tc.SyscallConn(); rerr == nil {
			var optErr error
			_ = raw.Control(func(fd uintptr) {
				optErr = applyIPTTLTOS(int(fd), s, network)
			})
			if optErr != nil {
				return optErr
			}
		}
	}
	if err := applyKeepAliveConfig(s, tc); err != nil {
		return err
	}
	if s.HasOption("nodelay") || s.HasOption("tcp-nodelay") {
		enabled := s.BoolOption("nodelay") || s.BoolOption("tcp-nodelay")
		if err := tc.SetNoDelay(enabled); err != nil {
			return fmt.Errorf("nodelay: %w", err)
		}
	}
	// Classic PH_LATE so-sndbuf-late / so-rcvbuf-late on the raw TCP fd
	// after connect()/accept(), before TLS/PROXY handshake. WrapCommon
	// still applies the same options on UNIX/UDP streams; a second
	// SO_SNDBUF set on this TCP conn is harmless.
	return ApplyLateSocketOptionsToConn(tc, s)
}

func ApplySetsockoptFD(fd int, spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) != 3 {
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

// ParseSizeT matches classic's strtoul-based TYPE_SIZE_T parser. In
// particular, an optional minus sign is converted modulo 2^64, so
// readbytes=-1 means the largest possible limit rather than a parse failure.
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
	// classic timeval: seconds with optional fractional part
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
// unlimited; a present but invalid value is an error (classic fail-closed).
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
