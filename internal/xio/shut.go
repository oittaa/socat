package xio

import (
	"context"
	"fmt"
	"sync"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func wrapShutPolicy(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return nil, err
	}
	return wrapTransferShut(config.Transfer.Shutdown, stream), nil
}

func wrapTransferShut(mode addrconfig.ShutdownMode, stream relay.Stream) relay.Stream {
	switch mode {
	case addrconfig.ShutdownNone:
		return shutNoneStream{Stream: stream}
	case addrconfig.ShutdownDown:
		return shutDownStream{Stream: stream}
	case addrconfig.ShutdownClose:
		return newShutCloseStream(stream)
	case addrconfig.ShutdownNull:
		return shutNullStream{Stream: stream}
	default:
		return stream
	}
}

// ShutNoneSelected reports that shut-none (or shut=none) is selected.
func ShutNoneSelected(s parse.Spec) bool {
	config, err := OpeningConfig(context.Background(), s)
	return err == nil && config.Transfer.Shutdown == addrconfig.ShutdownNone
}

// ShutDownSelected reports that shut-down (or shut=down) is selected.
func ShutDownSelected(s parse.Spec) bool {
	config, err := OpeningConfig(context.Background(), s)
	return err == nil && config.Transfer.Shutdown == addrconfig.ShutdownDown
}

// shutNoneStream makes ShutdownWrite a no-op.
type shutNoneStream struct{ relay.Stream }

func (s shutNoneStream) ShutdownWrite() error       { return nil }
func (s shutNoneStream) UnwrapStream() relay.Stream { return s.Stream }

// shutDownStream performs socket shutdown(SHUT_WR).
type shutDownStream struct{ relay.Stream }

func (s shutDownStream) ShutdownWrite() error {
	if err := shutdownWritePolicy(s.Stream); err != nil {
		return fmt.Errorf("shut-down: %w", err)
	}
	return nil
}
func (s shutDownStream) UnwrapStream() relay.Stream { return s.Stream }

// shutNullStream sends a 0-byte Write on ShutdownWrite. The write result
// is ignored; ShutdownWrite of the underlying stream is not called.
type shutNullStream struct {
	relay.Stream
}

func (s shutNullStream) UnwrapStream() relay.Stream { return s.Stream }

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
