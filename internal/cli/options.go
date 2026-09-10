package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

type helpOpt struct {
	name        string
	desc        string
	aliases     []string
	dynamicDesc func() string
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
	for _, def := range optionmeta.All() {
		if def.Isolation {
			continue
		}
		spec := addressOptionFromDef(def)
		for _, name := range cliSpellings(def) {
			key := strings.ToLower(name)
			if _, exists := options[key]; exists {
				panic("duplicate address option " + key)
			}
			options[key] = spec
		}
	}
	for _, name := range xio.TermiosOptionNames() {
		key := strings.ToLower(name)
		if _, ok := options[key]; ok {
			continue
		}
		options[key] = addressOption{optionCaps: capTermios}
	}
	return options
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
	// Same isolation names OpenSpec rejects; recognize them here so CLI
	// validation does not report "unknown option".
	if err := xio.RejectUnsupportedIsolation(spec); err != nil {
		return err
	}
	registration, registered := xio.AddressRegistrationForType(spec.Type)
	for _, option := range spec.Options {
		optionSpec, ok := lookupAddressOption(option)
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
	if err := xio.RejectUnsupportedListenBacklog(spec); err != nil {
		return err
	}
	for _, option := range spec.Options {
		optionSpec, ok := lookupAddressOption(option)
		if !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		// Prefer the public spelling so ipv6-join-group stays IPv6-only
		// even if Name was folded onto ip-add-membership.
		if registered && !xio.OptionSupportedOnAddress(registration, optionSpec.addressGroups, optionSpec.addressTypes, optionSpec.optionCaps) {
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

// lookupAddressOption prefers the original spelling so public names that
// share a parse fold still keep their own optionCaps. Unknown parse aliases
// fall back to the canonical Name.
func lookupAddressOption(option parse.Option) (addressOption, bool) {
	spelling := strings.ToLower(option.OriginalSpelling())
	if spec, ok := supportedAddressOptions[spelling]; ok {
		return spec, true
	}
	spec, ok := supportedAddressOptions[strings.ToLower(option.Name)]
	return spec, ok
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

func backlogListenAddressTypes() []string {
	return []string{
		"TCP-LISTEN", "TCP-L", "TCP4-LISTEN", "TCP4-L", "TCP6-LISTEN", "TCP6-L",
		"UNIX-LISTEN", "UNIX-L",
		"ABSTRACT-LISTEN", "ABSTRACT-L",
		"TLS-LISTEN", "TLS-L",
		"OPENSSL-LISTEN", "OPENSSL-L",
		"SSL-LISTEN", "SSL-L",
		"WS-LISTEN", "WS-L",
		"WSS-LISTEN", "WSS-L",
		"SOCKET-LISTEN",
		"SCTP-LISTEN", "SCTP-L", "SCTP4-LISTEN", "SCTP4-L", "SCTP6-LISTEN", "SCTP6-L",
		"VSOCK-LISTEN", "VSOCK-L",
	}
}

func resolverImplementationGroups() []string {
	return []string{
		xio.GroupTCP,
		xio.GroupUDP,
		xio.GroupRawIP,
		xio.GroupTLS,
		xio.GroupDTLS,
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
	return append(dtlsAddressTypes(), []string{
		"TLS", "TLS-CONNECT", "TLS-LISTEN", "TLS-L",
		"OPENSSL", "OPENSSL-CONNECT", "OPENSSL-LISTEN", "OPENSSL-L",
		"SSL", "SSL-CONNECT", "SSL-LISTEN", "SSL-L",
		"WSS", "WSS-CONNECT", "WSS-LISTEN", "WSS-L",
		"QUIC", "QUIC-CONNECT", "QUIC-LISTEN", "QUIC-L",
		"PROXY", "PROXY-CONNECT",
	}...)
}

func alpnAddressTypes() []string {
	return append(dtlsAddressTypes(), []string{
		"QUIC", "QUIC-CONNECT", "QUIC-LISTEN", "QUIC-L",
		"PROXY", "PROXY-CONNECT",
	}...)
}

func wsAddressTypes() []string {
	return []string{
		"WS", "WS-CONNECT", "WS-LISTEN", "WS-L",
		"WSS", "WSS-CONNECT", "WSS-LISTEN", "WSS-L",
	}
}

// handshakeAddressTypes is the Go extra handshake-timeout allow-list:
// addresses that actually perform TLS, DTLS, WebSocket, QUIC, PROXY, or SOCKS
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
		xio.GroupDTLS:   true,
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
	var groups []helpOptGroup
	for _, title := range optionmeta.HelpSectionOrder() {
		defs := optionmeta.AdvertisedIn(title)
		if len(defs) == 0 {
			continue
		}
		opts := make([]helpOpt, 0, len(defs))
		for _, def := range defs {
			opt := helpOpt{
				name:    def.Canonical,
				desc:    def.Desc,
				aliases: def.PublicAliases,
			}
			if def.DynamicDesc == "unix-socktype" {
				opt.dynamicDesc = xio.UnixSocktypeHelp
			}
			opts = append(opts, opt)
		}
		groups = append(groups, helpOptGroup{title: title, opts: opts})
	}
	return groups
}

func dtlsAddressTypes() []string {
	return []string{"OPENSSL-DTLS-CLIENT", "OPENSSL-DTLS-SERVER",
		"DTLS", "DTLS-C", "DTLS-CLIENT", "DTLS-CONNECT", "OPENSSL-DTLS-CONNECT",
		"DTLS-L", "DTLS-LISTEN", "DTLS-SERVER", "OPENSSL-DTLS-LISTEN"}
}
