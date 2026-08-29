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
	name                 string
	desc                 string
	aliases              []string
	addressTypes         []string
	restrictAddressTypes bool
	optionCaps           []string
	implementationGroups []string
	dynamicDesc          func() string
	validate             func(parse.Option) error
}

type helpOptGroup struct {
	title string
	opts  []helpOpt
}

type addressOption struct {
	validate             func(parse.Option) error
	addressGroups        []string
	addressTypes         []string
	restrictAddressTypes bool
	optionCaps           []string
	implementationGroups []string
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
			spec.restrictAddressTypes = option.restrictAddressTypes
			spec.optionCaps = option.optionCaps
			spec.implementationGroups = option.implementationGroups
			options[strings.ToLower(option.name)] = spec
			for _, alias := range option.aliases {
				options[strings.ToLower(alias)] = spec
			}
		}
	}
	for _, name := range extraHelpNames(true) {
		options[strings.ToLower(name)] = addressOption{}
	}
	// These names are deliberately recognized so tlsopen can return a precise
	// "not supported" error when their effective value requests unavailable
	// OpenSSL behavior. They must not be advertised as honored options in
	// -hh/-hhh. Parse aliases fold nicknames onto the openssl-* keys; listing
	// both keeps constructed Spec values working too.
	for _, name := range recognizedUnsupportedTLSNames {
		option := addressOption{addressGroups: tlsOptionAddressGroups()}
		switch parse.CanonicalOptionName(name) {
		case "openssl-fips", "openssl-pseudo":
			option.validate = validateOptionalBool
		case "openssl-method", "openssl-egd", "openssl-dhparam":
			option.validate = validateRequiredString
		case "openssl-maxfraglen", "openssl-maxsendfrag":
			option.validate = validateOptionalSignedInteger
		}
		options[name] = option
	}
	// Termios keywords are recognized where termios is unavailable so they
	// can be rejected, not silently accepted. They are not advertised:
	// hideOptGroup omits PTY/TERMIOS and TermiosHelpNames is empty there.
	if !xio.FeatureTERMIOS {
		for _, name := range xio.ClassicTermiosOptionNames() {
			if _, ok := options[name]; !ok {
				options[name] = addressOption{}
			}
		}
	}
	for _, name := range []string{"ip-recverr", "recverr", "iprecverr", "ipv6-recverr"} {
		options[name] = addressOption{}
	}
	for _, name := range xio.GetOnlyIPv4OptionNames() {
		options[name] = addressOption{}
	}
	return options
}

// recognizedUnsupportedTLSNames are OPENSSL spellings Go crypto/tls cannot
// honor. Parsed for a precise reject; never listed in -hhh as working.
var recognizedUnsupportedTLSNames = []string{
	"openssl-method", "opensslmethod", "method",
	"openssl-fips", "fips",
	"openssl-egd", "egd",
	"openssl-pseudo", "pseudo",
	"openssl-dhparam", "openssl-dhparams", "dhparam", "dhparams", "dh",
	"openssl-maxfraglen", "maxfraglen",
	"openssl-maxsendfrag", "maxsendfrag",
}

// optionAddressGroups limits only protocol-specific option families.
// Cross-cutting options stay broadly accepted: common wrappers apply them.
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
		spelling := strings.ToLower(option.OriginalSpelling())
		optionSpec, ok := supportedAddressOptions[name]
		if !ok {
			optionSpec, ok = supportedAddressOptions[spelling]
		}
		if !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		if registered && !optionImplementedForGroup(registration.Group, optionSpec.implementationGroups) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		if err := validateAddressOptionValue(option); err != nil {
			return fmt.Errorf("%s: %w", spec.Type, err)
		}
	}
	if err := xio.RejectUnsupportedIPAncillary(spec); err != nil {
		return err
	}
	if err := xio.RejectUnsupportedTermios(spec); err != nil {
		return err
	}
	if err := xio.RejectUnsupportedRecvErr(spec); err != nil {
		return err
	}
	if err := xio.ValidateDescriptorModeOptions(spec); err != nil {
		return err
	}
	for _, option := range spec.Options {
		name := strings.ToLower(option.Name)
		spelling := strings.ToLower(option.OriginalSpelling())
		optionSpec, ok := supportedAddressOptions[name]
		if !ok {
			optionSpec = supportedAddressOptions[spelling]
		}
		// Catalog intersection is spelling-specific: ipv6-join-group is
		// IPv6-only; ip-add-membership is IPv4+IPv6.
		if registered && !xio.OptionSupportedOnAddress(registration, spelling, optionSpec.addressGroups, optionSpec.addressTypes, optionSpec.optionCaps) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		// INTERFACE options also match TUN. restrictAddressTypes
		// (retrieve-vlan) is a hard allow-list so TUN is rejected at CLI.
		if registered && optionSpec.restrictAddressTypes && !addressTypeAllowed(registration.Name, optionSpec.addressTypes) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
	}
	if err := xio.RejectUnsupportedRemainingIPv4(spec); err != nil {
		return err
	}
	return nil
}

func addressTypeAllowed(addressType string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(addressType, candidate) {
			return true
		}
	}
	return false
}

// optionImplementedForGroup narrows socket-wide options to the address
// families that currently apply them. Without this guard the CLI would
// accept options an opener then silently ignores.
func optionImplementedForGroup(group string, implementationGroups []string) bool {
	if len(implementationGroups) == 0 {
		return true
	}
	for _, candidate := range implementationGroups {
		if group == candidate {
			return true
		}
	}
	return false
}

func validateAddressOptionValue(option parse.Option) error {
	name := strings.ToLower(option.Name)
	if optionSpec, ok := supportedAddressOptions[name]; ok && optionSpec.validate != nil {
		if err := optionSpec.validate(option); err != nil {
			return err
		}
	}
	return xio.ValidateTermiosOption(option)
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

func validateResNSAddr(option parse.Option) error {
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	_, err = xio.ParseResNSAddr(value)
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

// validateSizeT: base-0 parse, zero allowed.
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

func validateOptionalSignedInteger(option parse.Option) error {
	if !option.Has {
		return nil
	}
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	if _, err := strconv.ParseInt(value, 0, 64); err != nil {
		return fmt.Errorf("invalid %s %q", option.Name, value)
	}
	return nil
}

func validateOptionalByte(option parse.Option) error {
	if !option.Has {
		return nil
	}
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(value, 0, 64)
	if err != nil || n < 0 || n > 255 {
		return fmt.Errorf("invalid %s %q", option.Name, value)
	}
	return nil
}

func validateOptionalBool(option parse.Option) error {
	if !option.Has {
		return nil
	}
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	if value != "0" && value != "1" {
		return fmt.Errorf("invalid %s %q", option.Name, value)
	}
	return nil
}

func validateNoValue(option parse.Option) error {
	if option.Has {
		return fmt.Errorf("%s: no value permitted", option.Name)
	}
	return nil
}

func validateShutOption(option parse.Option) error {
	if !option.Has {
		return fmt.Errorf("shut: value required (none, down, close, or null)")
	}
	v := strings.ToLower(strings.TrimSpace(option.Value))
	switch v {
	case "none", "down", "close", "null":
		return nil
	case "0", "false", "no", "off", "":
		// =0 does not select a policy (same Active() rule as shut-*).
		return nil
	default:
		return fmt.Errorf("shut: invalid value %q (want none, down, close, or null)", option.Value)
	}
}

func validateIntegerRange(min, max int64) func(parse.Option) error {
	return func(option parse.Option) error {
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		n, err := strconv.ParseInt(value, 0, 64)
		if err != nil || n < min || n > max {
			return fmt.Errorf("invalid %s %q", option.Name, value)
		}
		return nil
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

// validateOptionalInt64 parses lseek/ftruncate offsets: a bare option is
// accepted and defaults to offset 1.
func validateOptionalInt64(option parse.Option) error {
	if !option.Has {
		return nil
	}
	return validateInt64(false)(option)
}

func splitSockoptOption(option parse.Option) (name, level, opt, rest string, err error) {
	name = strings.ToLower(option.Name)
	value, err := requiredOptionValue(option)
	if err != nil {
		return name, "", "", "", err
	}
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 {
		return name, "", "", "", fmt.Errorf("invalid %s %q (want level:optname:value)", name, value)
	}
	return name, parts[0], parts[1], parts[2], nil
}

func validateSockoptIntFields(name, value string, fields ...string) error {
	for _, field := range fields {
		if _, err := strconv.ParseInt(strings.TrimSpace(field), 0, 32); err != nil {
			return fmt.Errorf("invalid %s %q (want integer level:optname:value)", name, value)
		}
	}
	return nil
}

func validateSockoptBin(option parse.Option) error {
	name, level, opt, rest, err := splitSockoptOption(option)
	if err != nil {
		return err
	}
	if err := validateSockoptIntFields(name, option.Value, level, opt); err != nil {
		return err
	}
	if strings.TrimSpace(rest) == "" {
		return fmt.Errorf("invalid %s %q (want level:optname:value)", name, option.Value)
	}
	data, _, err := xio.ParseDalan(rest, 'i')
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", name, option.Value, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("invalid %s %q (empty dalan value)", name, option.Value)
	}
	return nil
}

func validateSockoptInt(option parse.Option) error {
	name, level, opt, rest, err := splitSockoptOption(option)
	if err != nil {
		return err
	}
	return validateSockoptIntFields(name, option.Value, level, opt, rest)
}

func validateSockoptString(option parse.Option) error {
	name, level, opt, _, err := splitSockoptOption(option)
	if err != nil {
		return err
	}
	return validateSockoptIntFields(name, option.Value, level, opt)
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

func resolverImplementationGroups() []string {
	return []string{
		xio.GroupTCP,
		xio.GroupUDP,
		xio.GroupRawIP,
		xio.GroupTLS,
		xio.GroupProxy,
		xio.GroupWebSocket,
		xio.GroupQUIC,
		xio.GroupSCTP,
	}
}

func resolverAddressTypes() []string {
	allowed := make(map[string]bool)
	for _, group := range resolverImplementationGroups() {
		allowed[group] = true
	}
	var names []string
	for _, registration := range xio.AddressRegistrations() {
		if allowed[registration.Group] {
			names = append(names, registration.Name)
		}
	}
	sort.Strings(names)
	return names
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

func wsAddressTypes() []string {
	return []string{
		"WS", "WS-CONNECT", "WS-LISTEN", "WS-L",
		"WSS", "WSS-CONNECT", "WSS-LISTEN", "WSS-L",
	}
}

// handshakeAddressTypes is the Go extra handshake-timeout allow-list:
// addresses that actually perform TLS, WebSocket, QUIC, PROXY, or SOCKS
// negotiation. TCP/UDP/OPEN/EXEC and other non-handshake types must reject
// the option rather than silently ignore it.
func handshakeAddressTypes() []string {
	seen := make(map[string]bool)
	var types []string
	add := func(names []string) {
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			types = append(types, name)
		}
	}
	add(tlsAddressTypes())
	add(wsAddressTypes())
	add(socksAddressTypes())
	return types
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
		xio.GroupVSOCK:  true,
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
	// Order is part of -hh/-hhh output. Split files own groups; this list
	// concatenates them in the original table order.
	var groups []helpOptGroup
	groups = append(groups, listenOptionGroups()...)
	groups = append(groups, socketOptionGroups()...)
	groups = append(groups, fileOptionGroups()...)
	groups = append(groups, processOptionGroups()...)
	groups = append(groups, transferOptionGroups()...)
	groups = append(groups, tlsOptionGroups()...)
	groups = append(groups, tunOptionGroups()...)
	return groups
}
