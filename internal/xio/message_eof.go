package xio

import (
	"io"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/relay"
)

// ZeroLengthMessageEOF maps a successful empty read on a connected datagram
// stream to io.EOF. A zero-length buffer is not a message and is left
// unchanged. Unconnected datagram addresses still ignore empty packets
// unless null-eof is set.
func ZeroLengthMessageEOF(n int, err error, bufLen int) (int, error) {
	if n == 0 && err == nil && bufLen > 0 {
		return 0, io.EOF
	}
	return n, err
}

// IgnoreEmptyDatagram reports whether a datagram receive should be discarded
// because it carried no payload and null-eof is not in effect. Unconnected
// *-RECVFROM waits use this so an empty packet does not lock the peer or
// complete a one-shot transfer.
func IgnoreEmptyDatagram(n int, err error, nullEOF bool) bool {
	return n == 0 && err == nil && !nullEOF
}

// WrapMessageEOF treats a successful empty Read as end of stream.
func WrapMessageEOF(st relay.Stream) relay.Stream {
	if ns, ok := st.(relay.NetStream); ok {
		return messageEOFNetStream{NetStream: ns}
	}
	return messageEOFStream{Stream: st}
}

// WrapConnectedMessageEOF wraps connected datagram sockets that are used as
// byte streams. Other socket types are left unchanged.
func WrapConnectedMessageEOF(socktype int, st relay.Stream) relay.Stream {
	if socktype == syscall.SOCK_DGRAM {
		return WrapMessageEOF(st)
	}
	return st
}

// messageEOFNetStream keeps LocalAddr and NetConn on connected datagram
// net.Conn streams.
type messageEOFNetStream struct {
	relay.NetStream
}

func (s messageEOFNetStream) Read(p []byte) (int, error) {
	n, err := s.NetStream.Read(p)
	return ZeroLengthMessageEOF(n, err, len(p))
}

func (s messageEOFNetStream) UnwrapStream() relay.Stream { return s.NetStream }

func (s messageEOFNetStream) NetConn() net.Conn { return s.Conn }

type messageEOFStream struct {
	relay.Stream
}

func (s messageEOFStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	return ZeroLengthMessageEOF(n, err, len(p))
}

func (s messageEOFStream) UnwrapStream() relay.Stream { return s.Stream }
