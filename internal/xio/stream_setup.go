package xio

import (
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// ApplyStreamFDOptions finishes descriptor lifecycle and late socket buffers.
// Lifecycle options already applied by the resource owner are left alone.
func ApplyStreamFDOptions(s parse.Spec, stream relay.Stream) error {
	if err := applyFDLifecycleToStream(s, stream); err != nil {
		return err
	}
	return ApplyStreamLateSocketOptions(s, stream)
}

// SetupStream finishes descriptor and connected options on an opened stream.
func SetupStream(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := ApplyStreamFDOptions(s, stream); err != nil {
		return nil, err
	}
	if err := applyGenericSetsockoptToStream(s, stream, SockoptPhaseConnected); err != nil {
		return nil, err
	}
	return WrapStream(s, stream, StreamSocketTimeouts)
}

// SetupConnectedStream finishes a stream whose connected options have already
// been applied or rejected by its opener.
func SetupConnectedStream(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := ApplyStreamFDOptions(s, stream); err != nil {
		return nil, err
	}
	return WrapStream(s, stream, StreamSocketTimeouts)
}

// ApplyStreamLateOptions finishes ACCEPT-FD after its descriptor, socket,
// and connected options have run on the accepted connection.
func ApplyStreamLateOptions(s parse.Spec, stream relay.Stream) error {
	if err := applyFDLifecycleLateToStream(s, stream); err != nil {
		return err
	}
	return ApplyStreamLateSocketOptions(s, stream)
}
