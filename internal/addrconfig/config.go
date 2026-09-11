// Package addrconfig decodes static address syntax into immutable settings.
package addrconfig

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

// Facts are registry-supplied address properties.
type Facts struct {
	Type   string
	Group  string
	Caps   []string
	Kind   AddressKind
	Role   AddressRole
	Family IPFamily
}

// Address is immutable prepared address data.
type Address struct {
	Type   string
	Params []string
	Facts  Facts

	Common   Common
	Transfer Transfer
	File     File
	Process  Process
	Terminal Terminal
	Network  Network
	TLS      TLS
	Proxy    Proxy
}

// decoder holds last-occurrence bookkeeping that must not leak onto the
// prepared Address openers and fork sessions share.
type decoder struct {
	Address
	optionIndex            int
	cr                     lineConversion
	crnl                   lineConversion
	crorlf                 lineConversion
	unsupported            []TLSUnsupported
	wsPositionalPath       string
	socksPositionalPort    PortTarget
	socksPositionalPortSet bool
}

type lineConversion struct {
	set    bool
	active bool
	index  int
	ending LineEnding
}

// Common contains settings shared by several address families.
type Common struct {
	Retry            Retry
	Fork             OptionalBool
	NoFork           OptionalBool
	ConnectTimeout   OptionalDuration
	HandshakeTimeout OptionalDuration
	AcceptTimeout    OptionalDuration
	ReadTimeout      OptionalDuration
	WriteTimeout     OptionalDuration
	MaxChildren      OptionalInt
	ChildrenShutup   OptionalInt
	Binary           OptionalBool
	Text             OptionalBool
	NetNamespace     OptionalString
	NameServer       NameServer
	UseVC            OptionalBool
	AddrConfig       OptionalBool
	Passive          OptionalBool
	V4Mapped         OptionalBool
	AddrInfoAll      OptionalBool
	IPv6V6Only       OptionalBool
}

// Retry is the reopen policy before Policy() resolves it.
type Retry struct {
	Forever  OptionalBool
	Count    OptionalInt
	Interval time.Duration
}

// RetryPolicy is the resolved retry loop. MaxAttempts 0 is unlimited.
type RetryPolicy struct {
	MaxAttempts uint64
	Interval    time.Duration
}

// Policy resolves retry=N over forever regardless of option order.
func (r Retry) Policy() RetryPolicy {
	p := RetryPolicy{MaxAttempts: 1, Interval: r.Interval}
	if r.Forever.Set && r.Forever.Value {
		p.MaxAttempts = 0
	}
	if r.Count.Set {
		if r.Count.Value < 0 {
			p.MaxAttempts = 0
		} else {
			p.MaxAttempts = uint64(r.Count.Value) + 1
		}
	}
	return p
}

// Transfer contains stream wrapper choices resolved before a resource opens.
type Transfer struct {
	ReadBytes  OptionalUint64
	Escape     OptionalByte
	IgnoreEOF  OptionalBool
	NullEOF    OptionalBool
	EndClose   OptionalBool
	LineEnding LineEnding
	Shutdown   ShutdownMode
}

// LineEnding selects one transfer conversion. Zero leaves the stream raw.
type LineEnding uint8

const (
	LineEndingRaw LineEnding = iota
	LineEndingCR
	LineEndingCRNL
	LineEndingCROrLF
)

// ShutdownMode selects a half-close policy; zero preserves the address default.
type ShutdownMode uint8

const (
	ShutdownDefault ShutdownMode = iota
	ShutdownNone
	ShutdownDown
	ShutdownClose
	ShutdownNull
)

// Optional preserves absence separately from a zero value.
type Optional[T any] struct {
	Set   bool
	Value T
}

type (
	OptionalBool     = Optional[bool]
	OptionalInt      = Optional[int]
	OptionalUint64   = Optional[uint64]
	OptionalUint32   = Optional[uint32]
	OptionalByte     = Optional[byte]
	OptionalDuration = Optional[time.Duration]
	OptionalString   = Optional[string]
)

// Decode transforms shared option families without acquiring resources.
func Decode(spec parse.Spec, facts Facts) (Address, error) {
	d := decoder{
		Address: Address{
			Type:   facts.Type,
			Params: append([]string(nil), spec.Params...),
			Facts: Facts{
				Type:   facts.Type,
				Group:  facts.Group,
				Caps:   append([]string(nil), facts.Caps...),
				Kind:   facts.Kind,
				Role:   facts.Role,
				Family: facts.Family,
			},
			Common: Common{
				Retry: Retry{Interval: time.Second},
			},
		},
	}

	if err := decodeNetwork(&d, spec); err != nil {
		return Address{}, fmt.Errorf("%s: %w", facts.Type, err)
	}
	for _, option := range spec.Options {
		if err := decodeOption(&d, option); err != nil {
			return Address{}, fmt.Errorf("%s: %w", facts.Type, err)
		}
	}
	if err := finishDecode(&d); err != nil {
		return Address{}, fmt.Errorf("%s: %w", facts.Type, err)
	}
	if d.Common.MaxChildren.Set && (!d.Common.Fork.Set || !d.Common.Fork.Value) {
		return Address{}, fmt.Errorf("%s: option max-children not allowed without option fork", facts.Type)
	}
	return d.Address, nil
}

func finishDecode(d *decoder) error {
	resolveLineEnding(d)
	resolveUnsupportedTLS(d)
	if d.TLS.WSPath.Set && d.TLS.WSPath.Value == "" && d.wsPositionalPath != "" {
		d.TLS.WSPath.Value = d.wsPositionalPath
	}
	if d.Proxy.SOCKSPortSet && d.Proxy.SOCKSPort.Text() == "" && d.socksPositionalPortSet {
		d.Proxy.SOCKSPort = d.socksPositionalPort
	}
	if d.TLS.MaxVersion != 0 && d.TLS.MinVersion > d.TLS.MaxVersion {
		return fmt.Errorf("minimum TLS protocol version exceeds maximum")
	}
	return nil
}

func decodeOption(d *decoder, o parse.Option) error {
	d.optionIndex++
	a := &d.Address
	name := optionIdentity(o)
	if _, ok := optionmeta.IsolationCanonical(name); ok {
		spelling := o.OriginalSpelling()
		if spelling == "" {
			spelling = o.Name
		}
		return fmt.Errorf("option %q is not supported (%s)", spelling, optionmeta.IsolationUnsupportedReason)
	}
	if handled, err := decodeFileProcess(a, o); handled {
		return err
	}
	if handled, err := decodeTerminal(a, o); handled {
		return err
	}
	if handled, err := decodeNetworkOption(a, o); handled {
		return err
	}
	if handled, err := decodeProtocolOption(d, o); handled {
		return err
	}
	switch name {
	case "fork":
		a.Common.Fork = activeBool(o)
		return nil
	case "nofork":
		a.Common.NoFork = activeBool(o)
		return nil
	case "max-children":
		n, err := requiredInt(o, 0)
		if err != nil {
			return err
		}
		a.Common.MaxChildren = OptionalInt{Set: true, Value: n}
		return nil
	case "children-shutup":
		if !o.Has {
			a.Common.ChildrenShutup = OptionalInt{Set: true, Value: 1}
			return nil
		}
		n, err := requiredInt(o, 0)
		if err != nil {
			return err
		}
		a.Common.ChildrenShutup = OptionalInt{Set: true, Value: n}
		return nil
	case "forever":
		a.Common.Retry.Forever = activeBool(o)
		return nil
	case "retry":
		n, err := requiredInt(o, -1)
		if err != nil {
			return err
		}
		a.Common.Retry.Count = OptionalInt{Set: true, Value: n}
		return nil
	case "interval":
		d, err := duration(o)
		if err != nil {
			return err
		}
		a.Common.Retry.Interval = d
		return nil
	case "connect-timeout":
		return decodeDuration(&a.Common.ConnectTimeout, o)
	case "handshake-timeout":
		return decodeDuration(&a.Common.HandshakeTimeout, o)
	case "accept-timeout":
		return decodeDuration(&a.Common.AcceptTimeout, o)
	case "readbytes":
		n, err := sizeT(o)
		if err != nil {
			return err
		}
		a.Transfer.ReadBytes = OptionalUint64{Set: true, Value: n}
		return nil
	case "escape":
		b, err := escapeByte(o)
		if err != nil {
			return err
		}
		a.Transfer.Escape = OptionalByte{Set: true, Value: b}
		return nil
	case "ignoreeof", "null-eof":
		v := activeBool(o)
		if name == "ignoreeof" {
			a.Transfer.IgnoreEOF = v
		} else {
			a.Transfer.NullEOF = v
		}
		return nil
	case "end-close":
		v, err := optionalBool(o)
		a.Transfer.EndClose = v
		return err
	case "cr":
		if o.Has {
			return fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		d.cr = lineConversion{set: true, active: true, index: d.optionIndex, ending: LineEndingCR}
		return nil
	case "crnl":
		if o.Has {
			return fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		d.crnl = lineConversion{set: true, active: true, index: d.optionIndex, ending: LineEndingCRNL}
		return nil
	case "crorlf":
		v := activeBool(o)
		d.crorlf = lineConversion{set: true, active: v.Value, index: d.optionIndex, ending: LineEndingCROrLF}
		return nil
	case "shut-none":
		return decodeNamedShutdown(&a.Transfer.Shutdown, o, ShutdownNone)
	case "shut-down":
		return decodeNamedShutdown(&a.Transfer.Shutdown, o, ShutdownDown)
	case "shut-close":
		return decodeNamedShutdown(&a.Transfer.Shutdown, o, ShutdownClose)
	case "shut-null":
		return decodeNamedShutdown(&a.Transfer.Shutdown, o, ShutdownNull)
	case "shut":
		return decodeShutdown(&a.Transfer.Shutdown, o)
	case "binary", "text":
		v, err := optionalBool(o)
		if name == "binary" {
			a.Common.Binary = v
		} else {
			a.Common.Text = v
		}
		return err
	case "netns":
		v, err := requiredString(o)
		if err == nil {
			a.Common.NetNamespace = OptionalString{Set: true, Value: v}
		}
		return err
	case "res-nsaddr":
		v, err := requiredString(o)
		if err != nil {
			return err
		}
		ns, err := ParseResNSAddr(v)
		if err != nil {
			return err
		}
		a.Common.NameServer = ns
		return nil
	case "res-usevc", "ai-addrconfig", "ai-passive", "ai-v4mapped", "ai-all":
		v, err := optionalBool(o)
		switch name {
		case "res-usevc":
			a.Common.UseVC = v
		case "ai-addrconfig":
			a.Common.AddrConfig = v
		case "ai-passive":
			a.Common.Passive = v
		case "ai-v4mapped":
			a.Common.V4Mapped = v
		default:
			a.Common.AddrInfoAll = v
		}
		return err
	}
	return nil
}

func resolveLineEnding(d *decoder) {
	last := -1
	ending := LineEndingRaw
	consider := func(c lineConversion) {
		if c.set && c.active && c.index >= last {
			last = c.index
			ending = c.ending
		}
	}
	consider(d.cr)
	consider(d.crnl)
	consider(d.crorlf)
	d.Transfer.LineEnding = ending
}

func optionIdentity(o parse.Option) string {
	for _, spelling := range []string{o.OriginalSpelling(), o.Name} {
		if def, ok := optionmeta.Lookup(spelling); ok {
			return def.Canonical
		}
	}
	return strings.ToLower(strings.TrimSpace(o.Name))
}

func decodeDuration(dst *OptionalDuration, o parse.Option) error {
	d, err := duration(o)
	if err != nil {
		return err
	}
	*dst = OptionalDuration{Set: true, Value: d}
	return nil
}

func decodeNamedShutdown(dst *ShutdownMode, o parse.Option, mode ShutdownMode) error {
	v, err := optionalBool(o)
	if err == nil && v.Value {
		*dst = mode
	}
	return err
}

func decodeShutdown(dst *ShutdownMode, o parse.Option) error {
	if !o.Has {
		return fmt.Errorf("shut: value required (none, down, close, or null)")
	}
	switch strings.ToLower(strings.TrimSpace(o.Value)) {
	case "none":
		*dst = ShutdownNone
	case "down":
		*dst = ShutdownDown
	case "close":
		*dst = ShutdownClose
	case "null":
		*dst = ShutdownNull
	case "0", "false", "no", "off", "":
	default:
		return fmt.Errorf("shut: invalid value %q (want none, down, close, or null)", o.Value)
	}
	return nil
}

func optionalBool(o parse.Option) (OptionalBool, error) {
	if !o.Has {
		return OptionalBool{Set: true, Value: true}, nil
	}
	v := strings.TrimSpace(o.Value)
	switch v {
	case "0":
		return OptionalBool{Set: true}, nil
	case "1":
		return OptionalBool{Set: true, Value: true}, nil
	default:
		return OptionalBool{}, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
}

func activeBool(o parse.Option) OptionalBool {
	if !o.Has {
		return OptionalBool{Set: true, Value: true}
	}
	v := strings.ToLower(strings.TrimSpace(o.Value))
	return OptionalBool{Set: true, Value: v != "" && v != "0" && v != "false" && v != "no" && v != "off"}
}

func optionText(o parse.Option) string {
	if !o.Has {
		return "1"
	}
	return o.Value
}

func requiredString(o parse.Option) (string, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return "", fmt.Errorf("option %q requires a value", o.OriginalSpelling())
	}
	return o.Value, nil
}

func requiredInt(o parse.Option, min int) (int, error) {
	value, err := requiredString(o)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(value), 0, 64)
	if err != nil || n < int64(min) || n > int64(math.MaxInt) {
		return 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), value)
	}
	return int(n), nil
}

func duration(o parse.Option) (time.Duration, error) {
	value, err := requiredString(o)
	if err != nil {
		return 0, err
	}
	d, err := ParseDuration(value)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), value)
	}
	return d, nil
}

func ParseDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		max := float64(math.MaxInt64) / float64(time.Second)
		if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > max || seconds < -max {
			return 0, fmt.Errorf("duration out of range")
		}
		return time.Duration(seconds * float64(time.Second)), nil
	}
	return time.ParseDuration(value)
}

func sizeT(o parse.Option) (uint64, error) {
	value, err := requiredString(o)
	if err != nil {
		return 0, err
	}
	n, err := ParseSizeT(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
	return n, nil
}

// ParseSizeT parses an unsigned size; a leading minus wraps modulo 2^64.
func ParseSizeT(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty value")
	}
	negative := value[0] == '-'
	if negative || value[0] == '+' {
		value = value[1:]
		if value == "" {
			return 0, fmt.Errorf("invalid value")
		}
	}
	n, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return 0, err
	}
	if negative {
		return -n, nil
	}
	return n, nil
}

func escapeByte(o parse.Option) (byte, error) {
	value, err := requiredString(o)
	if err != nil {
		return 0, err
	}
	if n, err := strconv.ParseUint(value, 0, 8); err == nil {
		return byte(n), nil
	}
	if len(value) == 1 {
		return value[0], nil
	}
	return 0, fmt.Errorf("escape: invalid value %q", o.Value)
}
