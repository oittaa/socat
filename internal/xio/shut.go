package xio

import (
	"fmt"
	"strings"
	"sync"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// shutPolicy is classic howtoshut (xio.h XIOSHUT_*). Unspecified keeps the
// address-dependent default (TCP half-close, UDP no-op in this port).
//
// Classic man documents shut-none[=<bool>] (and the other shut-* the same way).
// C TYPE_CONST rejects any assignment ("no value permitted") in parseopts
// (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same arm). This port follows
// the documented bool form: omitted value selects the policy; =0/false/no/off
// does not. Last active occurrence across shut-* and Go-only shut= wins.
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

// ShutNoneSelected reports classic howtoshut=none for EXEC child cleanup.
func ShutNoneSelected(s parse.Spec) bool {
	p, err := selectedShutPolicy(s)
	return err == nil && p == shutNone
}

// shutNoneStream makes ShutdownWrite a no-op (classic XIOSHUT_NONE).
type shutNoneStream struct{ relay.Stream }

func (s shutNoneStream) ShutdownWrite() error       { return nil }
func (s shutNoneStream) UnwrapStream() relay.Stream { return s.Stream }
func (s shutNoneStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

// shutDownStream performs socket-style ShutdownWrite (classic XIOSHUT_DOWN).
type shutDownStream struct{ relay.Stream }

func (s shutDownStream) ShutdownWrite() error       { return shutdownWritePolicy(s.Stream) }
func (s shutDownStream) UnwrapStream() relay.Stream { return s.Stream }
func (s shutDownStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

// shutNullStream sends a 0-byte Write on ShutdownWrite (classic XIOSHUT_NULL).
type shutNullStream struct {
	relay.Stream
}

func (s shutNullStream) UnwrapStream() relay.Stream { return s.Stream }
func (s shutNullStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

func (s shutNullStream) ShutdownWrite() error {
	_, _ = s.Write(nil) // 0-byte datagram
	return s.Stream.ShutdownWrite()
}

// shutCloseStream turns a directional half-close into a full descriptor
// close. This is required for SO_LINGER=0 to generate the immediate reset
// requested by classic shut-close (XIOSHUT_CLOSE).
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
