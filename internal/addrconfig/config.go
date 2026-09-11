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

// Facts are the semantic properties supplied by the address registry.
// They are intentionally explicit: the decoder must not infer them from a
// keyword prefix or a help spelling.
type Facts struct {
	Type  string
	Group string
	Caps  []string
}

// Address is immutable prepared address data. Params retain only positional
// payloads (paths, hosts, commands, and similar strings); option values are
// decoded into the groups below.
type Address struct {
	Type   string
	Params []string
	Raw    string
	Facts  Facts

	Common    Common
	Transfer  Transfer
	File      File
	Process   Process
	Terminal  Terminal
	Network   Network
	TLS       TLS
	DTLS      DTLS
	Proxy     Proxy
	WebSocket WebSocket
}

// Common contains settings shared by several address families.
type Common struct {
	Retry             Retry
	Fork              Fork
	Timeouts          Timeouts
	MaxChildren       OptionalInt
	ChildrenShutup    OptionalInt
	DescriptorMode    DescriptorMode
	Binary            OptionalBool
	Text              OptionalBool
	NetNamespace      OptionalString
	Resolver          Resolver
	ConnectBind       OptionalString
	SourcePort        OptionalString
	ProtocolFamily    OptionalString
	IPv6V6Only        OptionalBool
	ReadSocketBuffer  OptionalInt
	WriteSocketBuffer OptionalInt
}

// Retry is ready for every reopen. The resolved fields preserve an explicit
// retry count separately from forever because retry always takes precedence.
type Retry struct {
	Forever  OptionalBool
	Count    OptionalInt
	Interval time.Duration
}

// RetryPolicy is the fully resolved retry loop configuration. MaxAttempts
// zero represents an unlimited loop.
type RetryPolicy struct {
	MaxAttempts uint64
	Interval    time.Duration
}

// Policy resolves retry's documented precedence: retry=N overrides forever,
// including when the options appeared in the opposite source order.
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

// Fork retains the distinction between a missing flag and an enabled flag
// where an address-specific default needs it.
type Fork struct {
	Enabled OptionalBool
	NoFork  OptionalBool
}

// Timeouts hold already-parsed address timeouts. A set zero duration means
// explicitly disabled where the relevant address supports that state.
type Timeouts struct {
	Connect   OptionalDuration
	Handshake OptionalDuration
	Accept    OptionalDuration
	Read      OptionalDuration
	Write     OptionalDuration
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

// DescriptorMode selects the platform descriptor conversion, if explicitly
// requested. It is separate from transport text transformations.
type DescriptorMode uint8

const (
	DescriptorModeDefault DescriptorMode = iota
	DescriptorModeBinary
	DescriptorModeText
)

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

// OptionalBool preserves absence separately from an explicit false.
type OptionalBool struct {
	Set   bool
	Value bool
}

type OptionalInt struct {
	Set   bool
	Value int
}

type OptionalUint64 struct {
	Set   bool
	Value uint64
}

// OptionalUint32 preserves absence separately from an explicit zero.
type OptionalUint32 struct {
	Set   bool
	Value uint32
}

type OptionalByte struct {
	Set   bool
	Value byte
}

type OptionalDuration struct {
	Set   bool
	Value time.Duration
}

type OptionalString struct {
	Set   bool
	Value string
}

// Resolver retains unresolved names and resolver policies. Names are resolved
// by the resource owner at its existing execution point.
type Resolver struct {
	NameServer OptionalString
	UseVC      OptionalBool
	AddrConfig OptionalBool
	Passive    OptionalBool
	V4Mapped   OptionalBool
	All        OptionalBool
}

// Decode transforms the option families that every transport shares. Callers
// pass facts after registry resolution; parsing and decoding itself perform no
// resource acquisition.
func Decode(spec parse.Spec, facts Facts) (Address, error) {
	a := Address{
		Type:   facts.Type,
		Params: append([]string(nil), spec.Params...),
		Raw:    spec.Raw,
		Facts: Facts{
			Type:  facts.Type,
			Group: facts.Group,
			Caps:  append([]string(nil), facts.Caps...),
		},
		Common: Common{
			Retry: Retry{Interval: time.Second},
		},
	}

	if err := decodeNetwork(&a, spec); err != nil {
		return Address{}, fmt.Errorf("%s: %w", facts.Type, err)
	}
	for _, option := range spec.Options {
		if err := decodeOption(&a, option); err != nil {
			return Address{}, fmt.Errorf("%s: %w", facts.Type, err)
		}
	}
	if a.Common.MaxChildren.Set && (!a.Common.Fork.Enabled.Set || !a.Common.Fork.Enabled.Value) {
		return Address{}, fmt.Errorf("%s: option max-children not allowed without option fork", facts.Type)
	}
	return a, nil
}

func decodeOption(a *Address, o parse.Option) error {
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
	if handled, err := decodeProtocolOption(a, o); handled {
		return err
	}
	switch name {
	case "fork":
		v := activeBool(o)
		a.Common.Fork.Enabled = v
		return nil
	case "nofork":
		v := activeBool(o)
		a.Common.Fork.NoFork = v
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
		return decodeDuration(&a.Common.Timeouts.Connect, o)
	case "handshake-timeout":
		return decodeDuration(&a.Common.Timeouts.Handshake, o)
	case "accept-timeout":
		return decodeDuration(&a.Common.Timeouts.Accept, o)
	case "rcvtimeo":
		return decodeDuration(&a.Common.Timeouts.Read, o)
	case "sndtimeo":
		return decodeDuration(&a.Common.Timeouts.Write, o)
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
	case "ignoreeof":
		v := activeBool(o)
		a.Transfer.IgnoreEOF = v
		return nil
	case "null-eof":
		v := activeBool(o)
		a.Transfer.NullEOF = v
		return nil
	case "end-close":
		v, err := optionalBool(o)
		a.Transfer.EndClose = v
		return err
	case "cr":
		if o.Has {
			return fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		a.Transfer.LineEnding = LineEndingCR
		return nil
	case "crnl":
		if o.Has {
			return fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		a.Transfer.LineEnding = LineEndingCRNL
		return nil
	case "crorlf":
		v := activeBool(o)
		if v.Value {
			a.Transfer.LineEnding = LineEndingCROrLF
		}
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
	case "binary":
		v, err := optionalBool(o)
		if err != nil {
			return err
		}
		a.Common.Binary = v
		if v.Value {
			a.Common.DescriptorMode = DescriptorModeBinary
		}
		return nil
	case "text":
		v, err := optionalBool(o)
		if err != nil {
			return err
		}
		a.Common.Text = v
		if v.Value {
			a.Common.DescriptorMode = DescriptorModeText
		}
		return nil
	case "netns":
		v, err := requiredString(o)
		if err == nil {
			a.Common.NetNamespace = OptionalString{Set: true, Value: v}
		}
		return err
	case "res-nsaddr":
		v, err := requiredString(o)
		if err == nil {
			a.Common.Resolver.NameServer = OptionalString{Set: true, Value: v}
		}
		return err
	case "res-usevc":
		v, err := optionalBool(o)
		a.Common.Resolver.UseVC = v
		return err
	case "ai-addrconfig":
		v, err := optionalBool(o)
		a.Common.Resolver.AddrConfig = v
		return err
	case "ai-passive":
		v, err := optionalBool(o)
		a.Common.Resolver.Passive = v
		return err
	case "ai-v4mapped":
		v, err := optionalBool(o)
		a.Common.Resolver.V4Mapped = v
		return err
	case "ai-all":
		v, err := optionalBool(o)
		a.Common.Resolver.All = v
		return err
	}
	return nil
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
	d, err := parseDuration(value)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), value)
	}
	return d, nil
}

func parseDuration(value string) (time.Duration, error) {
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
	value = strings.TrimSpace(value)
	negative := value[0] == '-'
	if negative || value[0] == '+' {
		value = value[1:]
	}
	n, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
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
