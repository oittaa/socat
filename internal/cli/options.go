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
		// Lookups use Name (canonical). Spelling is preserved for later
		// spelling-specific group/phase checks; this function must not fold
		// ipv6-join-group onto ip-add-membership groups until that lands.
		name := strings.ToLower(option.Name)
		optionSpec, ok := supportedAddressOptions[name]
		if !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		if registered && !optionImplementedForGroup(registration.Group, optionSpec.implementationGroups) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		if registered && !xio.IPAncillarySupported(registration.Group, name) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
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

// implementationGroups narrows classic socket-wide options to the address
// families that currently apply them. Without this guard, classic's broad
// GROUP_SOCKET metadata would make the CLI accept options that an opener then
// silently ignores.
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
