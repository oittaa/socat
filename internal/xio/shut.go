package xio

import (
	"fmt"
	"strings"
	"sync"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// shutPolicy selects how ShutdownWrite behaves. Unspecified keeps the
// address-dependent default: TCP half-close; UDP-CONNECT and UDP-LISTEN
// send a zero-length datagram from those streams; other UDP addresses a no-op.
//
// shut-none[=<bool>] (and the other shut-* the same way): omitted value or
// =1 selects the policy; =0 does not. Other assignments are rejected. Last
// active occurrence across shut-* and Go-only shut=none|down|close|null wins.
type shutPolicy int

const (
	shutUnspecified shutPolicy = iota
	shutNone
	shutDown
	shutClose
	shutNull
)

func selectedShutPolicy(s parse.Spec) (shutPolicy, error) {
	for _, o := range s.Options {
		name := parse.CanonicalOptionName(o.Name)
		switch name {
		case "shut-none", "shut-down", "shut-close", "shut-null":
			if err := validateClassicOptionalBool(o); err != nil {
				return shutUnspecified, err
			}
		}
	}
	for _, o := range s.Options {
		if parse.CanonicalOptionName(o.Name) != "shut" || !o.Active() {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(o.Value))
		if !o.Has || v == "" || v == "1" || v == "true" || v == "yes" || v == "on" {
			return shutUnspecified, fmt.Errorf("shut: value required (none, down, close, or null)")
		}
		switch v {
		case "none", "down", "close", "null":
		default:
			return shutUnspecified, fmt.Errorf("shut: invalid value %q (want none, down, close, or null)", o.Value)
		}
	}
	seen := map[string]bool{}
	for i := len(s.Options) - 1; i >= 0; i-- {
		o := s.Options[i]
		name := parse.CanonicalOptionName(o.Name)
		switch name {
		case "shut-none", "shut-down", "shut-close", "shut-null", "shut":
		default:
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if !o.Active() {
			continue
		}
		p, ok := shutPolicyNamed(name, o.Value)
		if !ok {
			continue
		}
		return p, nil
	}
	return shutUnspecified, nil
}

func validateClassicOptionalBool(o parse.Option) error {
	if !o.Has {
		return nil
	}
	v := strings.TrimSpace(o.Value)
	if v == "" {
		return fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
	if v != "0" && v != "1" {
		return fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
	}
	return nil
}

func shutPolicyNamed(name, value string) (shutPolicy, bool) {
	switch name {
	case "shut-none":
		return shutNone, true
	case "shut-down":
		return shutDown, true
	case "shut-close":
		return shutClose, true
	case "shut-null":
		return shutNull, true
	case "shut":
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "none":
			return shutNone, true
		case "down":
			return shutDown, true
		case "close":
			return shutClose, true
		case "null":
			return shutNull, true
		default:
			return shutUnspecified, false
		}
	default:
		return shutUnspecified, false
	}
}

func wrapShutPolicy(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	p, err := selectedShutPolicy(s)
	if err != nil {
		return nil, err
	}
	switch p {
	case shutNone:
		return shutNoneStream{Stream: stream}, nil
	case shutDown:
		return shutDownStream{Stream: stream}, nil
	case shutClose:
		return newShutCloseStream(stream), nil
	case shutNull:
		return shutNullStream{Stream: stream}, nil
	default:
		return stream, nil
	}
}

// ShutNoneSelected reports that shut-none (or shut=none) is selected, for
// EXEC child cleanup.
func ShutNoneSelected(s parse.Spec) bool {
	p, err := selectedShutPolicy(s)
	return err == nil && p == shutNone
}

// shutNoneStream makes ShutdownWrite a no-op.
type shutNoneStream struct{ relay.Stream }

func (s shutNoneStream) ShutdownWrite() error       { return nil }
func (s shutNoneStream) UnwrapStream() relay.Stream { return s.Stream }
func (s shutNoneStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

// shutDownStream performs socket shutdown(SHUT_WR).
type shutDownStream struct{ relay.Stream }

func (s shutDownStream) ShutdownWrite() error {
	if err := shutdownWritePolicy(s.Stream); err != nil {
		return fmt.Errorf("shut-down: %w", err)
	}
	return nil
}
func (s shutDownStream) UnwrapStream() relay.Stream { return s.Stream }
func (s shutDownStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

// shutNullStream sends a 0-byte Write on ShutdownWrite. The write result
// is ignored; ShutdownWrite of the underlying stream is not called.
type shutNullStream struct {
	relay.Stream
}

func (s shutNullStream) UnwrapStream() relay.Stream { return s.Stream }
func (s shutNullStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

func (s shutNullStream) ShutdownWrite() error {
	_, _ = s.Write(nil) // result ignored; do not also half-close
	return nil
}

// shutCloseStream turns a directional half-close into a full descriptor
// close so SO_LINGER=0 can generate an immediate reset.
type shutCloseStream struct {
	relay.Stream
	once sync.Once
	err  error
}

func newShutCloseStream(stream relay.Stream) relay.Stream {
	return &shutCloseStream{Stream: stream}
}

func (s *shutCloseStream) close() error {
	s.once.Do(func() { s.err = s.Stream.Close() })
	return s.err
}

func (s *shutCloseStream) ShutdownWrite() error       { return s.close() }
func (s *shutCloseStream) Close() error               { return s.close() }
func (s *shutCloseStream) UnwrapStream() relay.Stream { return s.Stream }
func (s *shutCloseStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}
