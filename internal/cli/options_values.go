package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func validateOptionValue(kind optionmeta.ValueKind, option parse.Option) error {
	switch kind {
	case optionmeta.ValueNone:
		return nil
	case optionmeta.RequiredString:
		return validateRequiredString(option)
	case optionmeta.OptionalBool:
		return validateOptionalBool(option)
	case optionmeta.OptionalSignedInteger:
		return validateOptionalSignedInteger(option)
	case optionmeta.OptionalByte:
		return validateOptionalByte(option)
	case optionmeta.OptionalInteger0:
		return validateOptionalInteger(option, 0)
	case optionmeta.IntegerMin0:
		return validateInteger(option, 0)
	case optionmeta.IntegerMin1:
		return validateInteger(option, 1)
	case optionmeta.IntegerMinNeg1:
		return validateInteger(option, -1)
	case optionmeta.Duration:
		return validateDurationOption(option)
	case optionmeta.Octal777:
		return validateOctal(option, 0o777)
	case optionmeta.Octal7777:
		return validateOctal(option, 0o7777)
	case optionmeta.SizeT:
		return validateSizeT(option)
	case optionmeta.OptionalInt64:
		return validateOptionalInt64(option)
	case optionmeta.Int64:
		return validateInt64(option, false)
	case optionmeta.PositiveInt64:
		return validateInt64(option, true)
	case optionmeta.IntegerRange0_2:
		return validateIntegerRange(option, 0, 2)
	case optionmeta.IntegerRange256_65507:
		return validateIntegerRange(option, 256, 65507)
	case optionmeta.ResNSAddr:
		return validateResNSAddr(option)
	case optionmeta.NoValue:
		return validateNoValue(option)
	case optionmeta.Shut:
		return validateShutOption(option)
	case optionmeta.SockoptBin:
		return validateSockoptBin(option)
	case optionmeta.SockoptInt:
		return validateSockoptInt(option)
	case optionmeta.SockoptString:
		return validateSockoptString(option)
	case optionmeta.GenericIoctl:
		return xio.ValidateGenericIoctl(option)
	case optionmeta.UnixTightSocklen:
		return validateUnixTightSocklen(option)
	default:
		panic(fmt.Sprintf("unknown option value kind %d", kind))
	}
}

func validateAddressOptionValue(option parse.Option) error {
	if def, ok := optionmeta.Lookup(option.Name); ok {
		if err := validateOptionValue(def.Value, option); err != nil {
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

func validateOctal(option parse.Option, max uint64) error {
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

func validateInteger(option parse.Option, min int64) error {
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

func validateOptionalInteger(option parse.Option, min int64) error {
	if !option.Has {
		return nil
	}
	return validateInteger(option, min)
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

func validateIntegerRange(option parse.Option, min, max int64) error {
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

func validateInt64(option parse.Option, requirePositive bool) error {
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

// validateOptionalInt64 parses lseek/ftruncate offsets: a bare option is
// accepted and defaults to offset 1.
func validateOptionalInt64(option parse.Option) error {
	if !option.Has {
		return nil
	}
	return validateInt64(option, false)
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
