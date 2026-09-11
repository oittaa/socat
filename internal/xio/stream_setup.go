package xio

import (
	"net"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// ApplyStreamFDOptions applies descriptor lifecycle and late socket buffers
// on a stream whose opener has not applied those stages.
func ApplyStreamFDOptions(s parse.Spec, stream relay.Stream) error {
	if err := applyFDLifecycleToStream(s, stream, FDSkip{}); err != nil {
		return err
	}
	return ApplyStreamLateSocketOptions(s, stream)
}

// WrapOpened applies late socket buffers and stream wrappers. The opener
// must already have applied descriptor lifecycle and connected sockopts
// (or rejected them).
func WrapOpened(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := ApplyStreamLateSocketOptions(s, stream); err != nil {
		return nil, err
	}
	return WrapStream(s, stream, StreamSocketTimeouts)
}

// WrapAfterFD finishes connected sockopts and wrapping after the opener
// applied descriptor lifecycle on the underlying file or connection.
func WrapAfterFD(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := applyGenericSetsockoptToStream(s, stream, SockoptPhaseConnected); err != nil {
		return nil, err
	}
	return WrapOpened(s, stream)
}

// SetupStream applies descriptor lifecycle and connected sockopts, then
// WrapOpened. Use when those stages have not been applied yet.
func SetupStream(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := applyFDLifecycleToStream(s, stream, FDSkip{}); err != nil {
		return nil, err
	}
	return WrapAfterFD(s, stream)
}

// SetupConnectedStream applies descriptor lifecycle then WrapOpened. Use
// when connected sockopts have already been applied or rejected.
func SetupConnectedStream(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := applyFDLifecycleToStream(s, stream, FDSkip{}); err != nil {
		return nil, err
	}
	return WrapOpened(s, stream)
}

// SetupAccepted applies remaining descriptor lifecycle (with skip) and
// connected sockopts on an accepted connection, then WrapOpened.
func SetupAccepted(s parse.Spec, c net.Conn, skip FDSkip) (relay.Stream, error) {
	st := relay.NetStream{Conn: c}
	if err := applyFDLifecycleToStream(s, st, skip); err != nil {
		return nil, err
	}
	return WrapAfterFD(s, st)
}

// ApplyStreamLateOptions finishes ACCEPT-FD after its descriptor, socket,
// and connected options have run on the accepted connection.
func ApplyStreamLateOptions(s parse.Spec, stream relay.Stream) error {
	if err := applyFDLifecycleLateToStream(s, stream); err != nil {
		return err
	}
	return ApplyStreamLateSocketOptions(s, stream)
}
