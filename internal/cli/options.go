package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

var supportedAddressOptions = buildSupportedAddressOptions()

func buildSupportedAddressOptions() map[string]struct{} {
	names := make(map[string]struct{})
	for _, group := range helpOptionGroups() {
		if hideOptGroup(group.title) {
			continue
		}
		for _, option := range group.opts {
			if hideOpt(option.name) {
				continue
			}
			names[strings.ToLower(option.name)] = struct{}{}
			for _, alias := range option.aliases {
				names[strings.ToLower(alias)] = struct{}{}
			}
		}
	}
	for _, name := range extraHelpNames(true) {
		names[strings.ToLower(name)] = struct{}{}
	}
	// These names are deliberately recognized so the relevant opener can
	// return a precise "not supported" error. They must not be advertised as
	// honored options in -hh/-hhh.
	for _, name := range []string{"openssl-method", "opensslmethod"} {
		names[name] = struct{}{}
	}
	return names
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
	for _, option := range spec.Options {
		name := strings.ToLower(option.Name)
		if _, ok := supportedAddressOptions[name]; !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		if err := validateAddressOptionValue(option); err != nil {
			return fmt.Errorf("%s: %w", spec.Type, err)
		}
	}
	return nil
}

func validateAddressOptionValue(option parse.Option) error {
	name := strings.ToLower(option.Name)
	switch name {
	case "mode", "perm":
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		n, err := strconv.ParseUint(value, 8, 32)
		if err != nil || n > 0o7777 {
			return fmt.Errorf("invalid %s %q", name, value)
		}
	case "umask":
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		n, err := strconv.ParseUint(value, 8, 32)
		if err != nil || n > 0o777 {
			return fmt.Errorf("invalid umask %q", value)
		}
	case "chdir":
		if _, err := requiredOptionValue(option); err != nil {
			return err
		}
	case "connect-timeout", "handshake-timeout", "accept-timeout", "interval", "pty-interval", "rcvtimeo":
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		d, err := parseDuration(value)
		if err != nil || d < 0 {
			return fmt.Errorf("invalid %s %q", name, value)
		}
	case "max-children", "backlog":
		if err := validateIntegerOption(option, 1); err != nil {
			return err
		}
	case "retry":
		if err := validateIntegerOption(option, -1); err != nil {
			return err
		}
	case "fdin", "fdout", "readbytes", "ftruncate", "mq-prio", "mq-maxmsg", "mq-msgsize":
		if err := validateIntegerOption(option, 0); err != nil {
			return err
		}
	case "socktype", "ip-ttl", "ipv6-unicast-hops":
		if err := validateIntegerOption(option, -1); err != nil {
			return err
		}
	case "ip-tos", "ipv6-tclass", "if-mtu":
		value, err := requiredOptionValue(option)
		if err != nil {
			return err
		}
		n, err := strconv.ParseInt(value, 0, 64)
		if err != nil || name == "if-mtu" && n <= 0 {
			return fmt.Errorf("invalid %s %q", name, value)
		}
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

func validateIntegerOption(option parse.Option, min int64) error {
	value, err := requiredOptionValue(option)
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < min {
		return fmt.Errorf("invalid %s %q", option.Name, value)
	}
	return nil
}
