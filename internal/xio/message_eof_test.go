package xio

import (
	"io"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/relay"
)

func TestIgnoreEmptyDatagram(t *testing.T) {
	t.Parallel()
	if !IgnoreEmptyDatagram(0, nil, false) {
		t.Fatal("expected empty datagram ignored without null-eof")
	}
	if IgnoreEmptyDatagram(0, nil, true) {
		t.Fatal("null-eof must keep empty datagram")
	}
	if IgnoreEmptyDatagram(1, nil, false) {
		t.Fatal("nonempty datagram must not be ignored")
	}
	if IgnoreEmptyDatagram(0, io.EOF, false) {
		t.Fatal("errors must not be treated as empty datagrams")
	}
}

func TestWrapConnectedMessageEOFOnlyDatagram(t *testing.T) {
	inner := relay.NetStream{}
	if got := WrapConnectedMessageEOF(syscall.SOCK_STREAM, inner); got != inner {
		t.Fatalf("stream wrap %T want NetStream", got)
	}
	if got := WrapConnectedMessageEOF(syscall.SOCK_SEQPACKET, inner); got != inner {
		t.Fatalf("seqpacket wrap %T want NetStream", got)
	}
	got := WrapConnectedMessageEOF(syscall.SOCK_DGRAM, inner)
	if _, ok := got.(messageEOFNetStream); !ok {
		t.Fatalf("dgram wrap %T want messageEOFNetStream", got)
	}
}
