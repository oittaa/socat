package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

type helpOpt struct {
	name         string
	desc         string
	aliases      []string
	addressTypes []string
	optionCaps   []string
	dynamicDesc  func() string
	validate     func(parse.Option) error
}

type helpOptGroup struct {
	title string
	opts  []helpOpt
}

type addressOption struct {
	validate      func(parse.Option) error
	addressGroups []string
	addressTypes  []string
	optionCaps    []string
}

var supportedAddressOptions = buildSupportedAddressOptions()

func buildSupportedAddressOptions() map[string]addressOption {
	options := make(map[string]addressOption)
	for _, group := range helpOptionGroups() {
		spec := addressOption{
			addressGroups: optionAddressGroups(group.title),
		}
		for _, option := range group.opts {
			spec.validate = option.validate
			spec.addressTypes = option.addressTypes
			spec.optionCaps = option.optionCaps
			options[strings.ToLower(option.name)] = spec
			for _, alias := range option.aliases {
				options[strings.ToLower(alias)] = spec
			}
		}
	}
	for _, name := range extraHelpNames(true) {
		options[strings.ToLower(name)] = addressOption{}
	}
	// These names are deliberately recognized so the relevant opener can
	// return a precise "not supported" error. They must not be advertised as
	// honored options in -hh/-hhh.
	for _, name := range []string{"openssl-method", "opensslmethod"} {
		options[name] = addressOption{addressGroups: tlsOptionAddressGroups()}
	}
	return options
}

// optionAddressGroups limits only protocol-specific option families. Classic
// cross-cutting options remain broadly accepted because many are applied by
// common wrappers rather than by one opener package.
func optionAddressGroups(title string) []string {
	switch title {
	case "TLS, WSS, and QUIC":
		return tlsOptionAddressGroups()
	case "WebSocket":
		return []string{xio.GroupWebSocket}
	case "PROXY and SOCKS":
		return []string{xio.GroupProxy}
	case "POSIX message queues":
		return []string{xio.GroupPOSIXMQ}
	case "TUN and INTERFACE":
		return []string{xio.GroupTUN}
	default:
		return nil
	}
}

func tlsOptionAddressGroups() []string {
	return []string{xio.GroupTLS, xio.GroupWebSocket, xio.GroupQUIC, xio.GroupProxy}
}

func validateChannelOptions(ch parse.Channel) error {
	if ch.Single != nil {
		return validateSpecOptions(*ch.Single)
	}
	if ch.Dual != nil {
		if err := validateSpecOptions(ch.Dual.Left); err != nil {
			return fmt.Errorf("dual left: %w", err)
		}
		if err := validateSpecOptions(ch.Dual.Right); err != nil {
			return fmt.Errorf("dual right: %w", err)
		}
	}
	return nil
}

func validateSpecOptions(spec parse.Spec) error {
	registration, registered := xio.AddressRegistrationForType(spec.Type)
	for _, option := range spec.Options {
		name := strings.ToLower(option.Name)
		optionSpec, ok := supportedAddressOptions[name]
		if !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		if registered && !xio.OptionSupportedOnAddress(registration, name, optionSpec.addressGroups, optionSpec.addressTypes, optionSpec.optionCaps) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		if err := validateAddressOptionValue(option); err != nil {
			return fmt.Errorf("%s: %w", spec.Type, err)
		}
	}
	return nil
}

func validateAddressOptionValue(option parse.Option) error {
	name := strings.ToLower(option.Name)
	if optionSpec, ok := supportedAddressOptions[name]; ok && optionSpec.validate != nil {
		return optionSpec.validate(option)
	}
	return nil
}

func requiredOptionValue(option parse.Option) (string, error) {
	value := strings.TrimSpace(option.Value)
	if !option.Has || value == "" {
		return "", fmt.Errorf("option %q requires a value", option.Name)
	}
	return value, nil
}

func validateRequiredString(option parse.Option) error {
	_, err := requiredOptionValue(option)
	return err
}

func validateOctal(max uint64) func(parse.Option) error {
	return func(option parse.Option) error {
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		n, err := strconv.ParseUint(value, 8, 32)
		if err != nil || n > max {
			return fmt.Errorf("invalid %s %q", strings.ToLower(option.Name), value)
		}
		return nil
	}
}

func validateDurationOption(option parse.Option) error {
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	d, err := parseDuration(value)
	if err != nil || d < 0 {
		return fmt.Errorf("invalid %s %q", strings.ToLower(option.Name), value)
	}
	return nil
}

func validateInteger(min int64) func(parse.Option) error {
	return func(option parse.Option) error {
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		n, err := strconv.ParseInt(value, 0, 64)
		if err != nil || n < min {
			return fmt.Errorf("invalid %s %q", option.Name, value)
		}
		return nil
	}
}

// validateSizeT matches classic TYPE_SIZE_T: base-0 parse, zero allowed.
func validateSizeT(option parse.Option) error {
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	_, err = xio.ParseSizeT(value)
	if err != nil {
		return fmt.Errorf("invalid %s %q", option.Name, value)
	}
	return nil
}

func validateOptionalInteger(min int64) func(parse.Option) error {
	return func(option parse.Option) error {
		if !option.Has {
			return nil
		}
		return validateInteger(min)(option)
	}
}

func validateInt64(requirePositive bool) func(parse.Option) error {
	return func(option parse.Option) error {
		name := strings.ToLower(option.Name)
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		n, err := strconv.ParseInt(value, 0, 64)
		if err != nil || (requirePositive && n <= 0) {
			return fmt.Errorf("invalid %s %q", name, value)
		}
		return nil
	}
}

func validateSockopt(option parse.Option) error {
	name := strings.ToLower(option.Name)
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return fmt.Errorf("invalid %s %q (want level:optname:value)", name, value)
	}
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return fmt.Errorf("invalid %s %q (want integer level:optname:value)", name, value)
		}
	}
	return nil
}

func proxyAddressTypes() []string {
	return []string{"PROXY", "PROXY-CONNECT"}
}

func socksAddressTypes() []string {
	return []string{
		"SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS5-CONNECT", "SOCKS5-LISTEN", "SOCKS5-BIND",
	}
}

func tcpStreamAddressTypes() []string {
	return []string{
		"TCP", "TCP-CONNECT", "TCP4", "TCP4-CONNECT", "TCP6", "TCP6-CONNECT",
		"TCP-LISTEN", "TCP-L", "TCP4-LISTEN", "TCP4-L", "TCP6-LISTEN", "TCP6-L",
		"TLS", "TLS-CONNECT", "TLS-LISTEN", "TLS-L",
		"OPENSSL", "OPENSSL-CONNECT", "OPENSSL-LISTEN", "OPENSSL-L",
		"SSL", "SSL-CONNECT", "SSL-LISTEN", "SSL-L",
		"WS", "WS-CONNECT", "WS-LISTEN", "WS-L",
		"WSS", "WSS-CONNECT", "WSS-LISTEN", "WSS-L",
		"PROXY", "PROXY-CONNECT",
		"SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS5-CONNECT", "SOCKS5-LISTEN", "SOCKS5-BIND",
	}
}

func tlsAddressTypes() []string {
	return []string{
		"TLS", "TLS-CONNECT", "TLS-LISTEN", "TLS-L",
		"OPENSSL", "OPENSSL-CONNECT", "OPENSSL-LISTEN", "OPENSSL-L",
		"SSL", "SSL-CONNECT", "SSL-LISTEN", "SSL-L",
		"WSS", "WSS-CONNECT", "WSS-LISTEN", "WSS-L",
		"QUIC", "QUIC-CONNECT", "QUIC-LISTEN", "QUIC-L",
		"PROXY", "PROXY-CONNECT",
	}
}

func alpnAddressTypes() []string {
	return []string{
		"QUIC", "QUIC-CONNECT", "QUIC-LISTEN", "QUIC-L",
		"PROXY", "PROXY-CONNECT",
	}
}

func fileOpenAddressTypes() []string {
	return []string{"OPEN", "FILE", "CREATE", "CREAT", "GOPEN"}
}

func fdOptionAddressTypes() []string {
	return []string{
		"STDIO", "STDIN", "STDOUT", "STDERR", "FD",
		"OPEN", "FILE", "CREATE", "CREAT", "GOPEN",
		"PIPE", "FIFO", "ECHO", "EXEC", "SYSTEM", "SHELL",
	}
}

func socketTimeoutAddressTypes() []string {
	allowedGroups := map[string]bool{
		xio.GroupTCP:    true,
		xio.GroupUDP:    true,
		xio.GroupRawIP:  true,
		xio.GroupUnix:   true,
		xio.GroupSocket: true,
		xio.GroupTLS:    true,
		xio.GroupProxy:  true,
		xio.GroupSCTP:   true,
	}
	allowedNames := map[string]bool{
		"INTERFACE":  true, // AF_PACKET socket in the TUN group
		"SOCKETPAIR": true, // socket-backed address in the file group
	}
	var names []string
	for _, registration := range xio.AddressRegistrations() {
		if allowedGroups[registration.Group] || allowedNames[registration.Name] {
			names = append(names, registration.Name)
		}
	}
	sort.Strings(names)
	return names
}

func helpOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Listen and connect", []helpOpt{
			{name: "reuseaddr", desc: "SO_REUSEADDR (default on for listen)", aliases: []string{"so-reuseaddr"}},
			{name: "reuseport", desc: "SO_REUSEPORT", aliases: []string{"so-reuseport"}},
			{name: "fork", desc: "new session per accept or client redial"},
			{name: "nofork", desc: "do not fork (single session)"},
			{name: "max-children", desc: "limit concurrent fork sessions (needs fork)", validate: validateInteger(1)},
			{name: "children-shutup", desc: "lower fork-child log severity", aliases: []string{"child-shutup"}, validate: validateOptionalInteger(0)},
			{name: "bind", desc: "local address or interface"},
			{name: "connect-timeout", desc: "connect timeout", validate: validateDurationOption},
			{name: "handshake-timeout", desc: "TLS, WebSocket, proxy, or SOCKS handshake timeout", validate: validateDurationOption},
			{name: "accept-timeout", desc: "listen accept timeout (exit 0)", aliases: []string{"listen-timeout"}, validate: validateDurationOption},
			{name: "backlog", desc: "listen backlog", addressTypes: []string{
				"TCP-LISTEN", "TCP-L", "TCP4-LISTEN", "TCP4-L", "TCP6-LISTEN", "TCP6-L",
				"SOCKET-LISTEN", "SCTP-LISTEN", "SCTP-L", "SCTP4-LISTEN", "SCTP4-L", "SCTP6-LISTEN", "SCTP6-L",
			}, validate: validateInteger(1)},
			{name: "pf", desc: "address family (4, 6, IP4, IP6, …)"},
			{name: "ai-addrconfig", desc: "getaddrinfo AI_ADDRCONFIG", aliases: []string{"addrconfig"}},
			{name: "ipv6-v6only", desc: "IPV6_V6ONLY"},
			{name: "retry", desc: "retry count on connect failure", validate: validateInteger(-1)},
			{name: "forever", desc: "retry without limit"},
			{name: "interval", desc: "retry or fork-redial interval", validate: validateDurationOption},
		}},
		{"Security filters", []helpOpt{
			{name: "range", desc: "accept only peers in this network"},
			{name: "sourceport", desc: "peer source port (listen) or bind port (connect)", aliases: []string{"sp"}},
			{name: "lowport", desc: "require or bind a low source port"},
			{name: "tcpwrap", desc: "apply hosts.allow / hosts.deny", aliases: []string{"tcpwrappers", "tcpwrapper", "libwrap", "wrap"}},
			{name: "tcpwrap-etc", desc: "directory of hosts.allow / hosts.deny", aliases: []string{"tcpwrap-dir"}},
			{name: "hosts-allow", desc: "allow table path", aliases: []string{"allow-table", "tcpwrap-hosts-allow-table"}},
			{name: "hosts-deny", desc: "deny table path", aliases: []string{"deny-table", "tcpwrap-hosts-deny-table"}},
		}},
		{"Sockets", []helpOpt{
			{name: "nodelay", desc: "TCP_NODELAY", aliases: []string{"tcp-nodelay"}, addressTypes: tcpStreamAddressTypes()},
			{name: "keepalive", desc: "SO_KEEPALIVE", aliases: []string{"so-keepalive"}, addressTypes: tcpStreamAddressTypes()},
			{name: "keepidle", desc: "TCP_KEEPIDLE idle time (requires keepalive)", aliases: []string{"so-keepidle", "tcp-keepidle"}, addressTypes: tcpStreamAddressTypes(), validate: validateDurationOption},
			{name: "keepintvl", desc: "TCP_KEEPINTVL probe interval", aliases: []string{"so-keepintvl", "tcp-keepintvl"}, addressTypes: tcpStreamAddressTypes(), validate: validateDurationOption},
			{name: "keepcnt", desc: "TCP_KEEPCNT probe count", aliases: []string{"so-keepcnt", "tcp-keepcnt"}, addressTypes: tcpStreamAddressTypes(), validate: validateInteger(1)},
			{name: "broadcast", desc: "SO_BROADCAST"},
			{name: "ip-add-membership", desc: "IPv4 multicast join"},
			{name: "ipv6-join-group", desc: "IPv6 multicast join"},
			{name: "setsockopt", desc: "raw setsockopt (level, opt, value)", validate: validateSockopt},
			{name: "setsockopt-listen", desc: "raw setsockopt before bind (level, opt, value)", aliases: []string{"sockopt-listen"}, validate: validateSockopt},
			{name: "so-timestamp", desc: "SO_TIMESTAMP ancillary", aliases: []string{"timestamp"}},
			{name: "ip-pktinfo", desc: "IP_PKTINFO", aliases: []string{"pktinfo"}},
			{name: "ip-recvttl", desc: "IP_RECVTTL", aliases: []string{"recvttl"}},
			{name: "ip-recvtos", desc: "IP_RECVTOS", aliases: []string{"recvtos"}},
			{name: "ip-recvopts", desc: "IP_RECVOPTS", aliases: []string{"recvopts"}},
			{name: "ip-ttl", desc: "IP_TTL", aliases: []string{"ttl", "ipttl"}, validate: validateInteger(-1)},
			{name: "ip-tos", desc: "IP_TOS", aliases: []string{"tos", "iptos"}, validate: validateInt64(false)},
			{name: "ip-options", desc: "IP_OPTIONS"},
			{name: "ipv6-recvpktinfo", desc: "IPV6_RECVPKTINFO", aliases: []string{"recvpktinfo"}},
			{name: "ipv6-recvhoplimit", desc: "IPV6_RECVHOPLIMIT", aliases: []string{"recvhoplimit"}},
			{name: "ipv6-recvtclass", desc: "IPV6_RECVTCLASS", aliases: []string{"recvtclass"}},
			{name: "ipv6-unicast-hops", desc: "IPV6_UNICAST_HOPS", aliases: []string{"unicast-hops"}, validate: validateInteger(-1)},
			{name: "ipv6-tclass", desc: "IPV6_TCLASS", aliases: []string{"tclass"}, validate: validateInt64(false)},
			{name: "rcvtimeo", desc: "per-operation socket receive timeout; retry after expiration", aliases: []string{"so-rcvtimeo"}, addressTypes: socketTimeoutAddressTypes(), validate: validateDurationOption},
			{name: "sndtimeo", desc: "per-operation socket send timeout; retry after expiration", aliases: []string{"so-sndtimeo"}, addressTypes: socketTimeoutAddressTypes(), validate: validateDurationOption},
			{name: "so-linger", desc: "SO_LINGER timeout in seconds", aliases: []string{"linger"}, addressTypes: socketTimeoutAddressTypes(), validate: validateInteger(0)},
		}},
		{"Files and UNIX", []helpOpt{
			{name: "rdonly", desc: "open read-only"},
			{name: "wronly", desc: "open write-only"},
			{name: "creat", desc: "create the file", aliases: []string{"create"}},
			{name: "excl", desc: "fail if the file exists"},
			{name: "append", desc: "open append", aliases: []string{"o-append"}, addressTypes: fileOpenAddressTypes()},
			{name: "trunc", desc: "truncate on open"},
			{name: "nonblock", desc: "O_NONBLOCK", aliases: []string{"o-nonblock"}},
			{name: "o-noatime", desc: "set O_NOATIME on the opened descriptor", aliases: []string{"noatime"}, addressTypes: fdOptionAddressTypes()},
			{name: "f-setpipe-sz", desc: "set Linux pipe capacity", aliases: []string{"pipesz"}, addressTypes: fdOptionAddressTypes(), validate: validateInteger(1)},
			{name: "mode", desc: "create mode bits", validate: validateOctal(0o7777)},
			{name: "perm", desc: "chmod after open", validate: validateOctal(0o7777)},
			{name: "ftruncate", desc: "truncate an opened file to this length", validate: validateInteger(0)},
			{name: "setlk", desc: "nonblocking whole-file write lock", aliases: []string{"f-setlk-wr"}},
			{name: "setlkw", desc: "blocking whole-file write lock", aliases: []string{"f-setlkw-wr"}},
			{name: "setlk-rd", desc: "nonblocking whole-file read lock", aliases: []string{"f-setlk-rd"}},
			{name: "setlkw-rd", desc: "blocking whole-file read lock", aliases: []string{"f-setlkw-rd"}},
			{name: "umask", desc: "umask during open or EXEC start", validate: validateOctal(0o777)},
			{name: "user", desc: "file owner"},
			{name: "group", desc: "file group"},
			{name: "unlink-early", desc: "unlink before bind/open"},
			{name: "unlink", desc: "unlink before open", aliases: []string{"delete", "remove"}},
			{name: "unlink-close", desc: "unlink on close"},
			{name: "unlink-late", desc: "unlink immediately after open"},
			{name: "unix-bind-tempname", desc: "bind a temporary UNIX name", aliases: []string{"bind-tempname"}},
			{name: "socktype", dynamicDesc: xio.UnixSocktypeHelp, aliases: []string{"so-type"}, validate: validateInteger(-1)},
		}},
		{"EXEC, SYSTEM, SHELL", []helpOpt{
			{name: "pipes", desc: "connect with pipes"},
			{name: "pty", desc: "run on a pseudo-terminal"},
			{name: "setsid", desc: "new session"},
			{name: "stderr", desc: "include child stderr"},
			{name: "fdin", desc: "child stdin fd number", validate: validateInteger(0)},
			{name: "fdout", desc: "child stdout fd number", validate: validateInteger(0)},
			{name: "shell", desc: "use a shell"},
			{name: "chdir", desc: "change directory before open or exec", validate: validateRequiredString},
			{name: "shut-none", desc: "do not kill the child on close"},
			{name: "shut-close", desc: "fully close instead of half-closing"},
			{name: "end-close", desc: "close on EOF"},
			{name: "shut", desc: "half-close mode"},
			{name: "shut-null", desc: "0-byte datagram as half-close"},
		}},
		{"PTY and TERMIOS", []helpOpt{
			{name: "link", desc: "symlink to the PTY slave", aliases: []string{"symbolic-link"}},
			{name: "cfmakeraw", desc: "raw termios (cfmakeraw)", aliases: []string{"raw"}},
			{name: "rawer", desc: "stricter raw termios"},
			{name: "echo", desc: "terminal echo"},
			{name: "opost", desc: "output post-processing"},
			{name: "ispeed", desc: "input baud"},
			{name: "ospeed", desc: "output baud"},
			{name: "tiocswinsz", desc: "window size cols:rows", aliases: []string{"winsz"}},
			{name: "pty-wait-slave", desc: "wait until the slave is open", aliases: []string{"wait-slave", "waitslave"}},
			{name: "pty-interval", desc: "poll interval while waiting for slave", validate: validateDurationOption},
			{name: "ctty", desc: "make the PTY the controlling tty", aliases: []string{"tiocsctty"}},
			// Classic compat spellings: accepted as no-ops. The PTY master
			// always comes from the platform default (/dev/ptmx or openpty),
			// so both spellings already describe what we do.
			{name: "ptmx", desc: "compat: /dev/ptmx is the default"},
			{name: "openpty", desc: "compat: openpty(3) semantics are the default"},
			{name: "escape", desc: "escape character"},
		}},
		{"Transfer", []helpOpt{
			{name: "crnl", desc: "convert CR/NL"},
			{name: "crlf", desc: "convert CR/LF"},
			{name: "crorlf", desc: "convert CR or LF"},
			{name: "ignoreeof", desc: "do not close on EOF", aliases: []string{"ignoreof"}},
			{name: "null-eof", desc: "treat a zero-length read as EOF"},
			{name: "readbytes", desc: "read at most N bytes", validate: validateSizeT},
		}},
		{"TLS, WSS, and QUIC", []helpOpt{
			{name: "cert", desc: "certificate file (PEM); required on listen", addressTypes: tlsAddressTypes()},
			{name: "key", desc: "private key file (PEM)", addressTypes: tlsAddressTypes()},
			{name: "cafile", desc: "CA file (PEM or DER)", aliases: []string{"ca"}, addressTypes: tlsAddressTypes()},
			{name: "capath", desc: "directory of CA certificates", aliases: []string{"tls-capath", "openssl-capath"}, addressTypes: tlsAddressTypes()},
			{name: "verify", desc: "verify the peer (default on; 0 skips)", addressTypes: tlsAddressTypes()},
			{name: "commonname", desc: "name to check (empty skips the name check)", aliases: []string{"tls-commonname", "openssl-commonname"}, addressTypes: tlsAddressTypes()},
			{name: "snihost", desc: "TLS SNI host name", aliases: []string{"tls-snihost", "openssl-snihost"}, addressTypes: tlsAddressTypes()},
			{name: "nosni", desc: "do not send SNI", aliases: []string{"tls-no-sni", "openssl-no-sni"}, addressTypes: tlsAddressTypes()},
			{name: "ciphers", desc: "TLS 1.2 cipher suite list", aliases: []string{"cipher", "openssl-cipherlist"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-min-proto-version", desc: "minimum TLS protocol version", aliases: []string{"min-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-max-proto-version", desc: "maximum TLS protocol version", aliases: []string{"max-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "alpn", desc: "QUIC or HTTP/2/3 proxy ALPN", addressTypes: alpnAddressTypes()},
		}},
		{"WebSocket", []helpOpt{
			{name: "path", desc: "WebSocket URL path"},
			{name: "origin", desc: "WebSocket Origin header"},
			{name: "protocol", desc: "WebSocket subprotocol"},
		}},
		{"PROXY and SOCKS", []helpOpt{
			{name: "proxyport", desc: "HTTP proxy port", addressTypes: proxyAddressTypes()},
			{name: "http-version", desc: "CONNECT HTTP version (1.0, 1.1, 2, 3)", addressTypes: proxyAddressTypes()},
			{name: "h2c", desc: "cleartext HTTP/2 CONNECT", addressTypes: proxyAddressTypes()},
			{name: "proxy-resolve", desc: "resolve CONNECT target locally", aliases: []string{"resolve"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization", desc: "proxy basic auth user:pass", aliases: []string{"proxyauth"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization-file", desc: "read proxy auth from a file", aliases: []string{"proxyauthfile"}, addressTypes: proxyAddressTypes()},
			{name: "socksport", desc: "SOCKS server port", addressTypes: socksAddressTypes()},
			{name: "socksuser", desc: "SOCKS user name", addressTypes: socksAddressTypes()},
			{name: "sockspass", desc: "SOCKS password", aliases: []string{"sockspassword"}, addressTypes: socksAddressTypes()},
		}},
		{"POSIX message queues", []helpOpt{
			{name: "mq-prio", desc: "message priority", aliases: []string{"posixmq-priority"}, validate: validateInteger(0)},
			{name: "mq-flush", desc: "drain the queue before use", aliases: []string{"posixmq-flush"}},
			{name: "mq-maxmsg", desc: "mq_maxmsg", aliases: []string{"posixmq-maxmsg"}, validate: validateInteger(0)},
			{name: "mq-msgsize", desc: "mq_msgsize", aliases: []string{"posixmq-msgsize"}, validate: validateInteger(0)},
		}},
		{"TUN and INTERFACE", []helpOpt{
			{name: "tun-device", desc: "path to the TUN clone device"},
			{name: "tun-name", desc: "TUN/TAP interface name"},
			{name: "tun-type", desc: "tun or tap"},
			{name: "iff-no-pi", desc: "no packet information header", aliases: []string{"no-pi"}},
			{name: "iff-up", desc: "bring the interface up", aliases: []string{"up"}},
			{name: "iff-broadcast", desc: "IFF_BROADCAST"},
			{name: "iff-debug", desc: "IFF_DEBUG"},
			{name: "iff-loopback", desc: "IFF_LOOPBACK", aliases: []string{"loopback"}},
			{name: "iff-pointopoint", desc: "IFF_POINTOPOINT", aliases: []string{"pointopoint"}},
			{name: "iff-running", desc: "IFF_RUNNING", aliases: []string{"running"}},
			{name: "iff-noarp", desc: "IFF_NOARP", aliases: []string{"noarp"}},
			{name: "iff-promisc", desc: "IFF_PROMISC", aliases: []string{"promisc"}},
			{name: "iff-allmulti", desc: "IFF_ALLMULTI", aliases: []string{"allmulti"}},
			{name: "iff-multicast", desc: "IFF_MULTICAST"},
			{name: "if-mtu", desc: "interface MTU", aliases: []string{"interface-mtu"}, validate: validateInt64(true)},
		}},
		{"Namespaces", []helpOpt{
			{name: "netns", desc: "open this address in a Linux network namespace"},
		}},
	}
}
