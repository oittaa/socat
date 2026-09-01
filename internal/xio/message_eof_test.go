package xio

import (
	"errors"
	"io"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/relay"
)

func TestZeroLengthMessageEOF(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name      string
		n, bufLen int
		err       error
		wantN     int
		wantEOF   bool
		wantSame  bool
	}{
		{name: "empty message", n: 0, bufLen: 16, wantEOF: true},
		{name: "empty buffer", n: 0, bufLen: 0, wantSame: true},
		{name: "payload", n: 4, bufLen: 16, wantN: 4, wantSame: true},
		{name: "error", n: 0, bufLen: 16, err: boom, wantSame: true},
		{name: "eof already", n: 0, bufLen: 16, err: io.EOF, wantSame: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := ZeroLengthMessageEOF(tt.n, tt.err, tt.bufLen)
			if tt.wantEOF {
				if n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("n=%d err=%v want EOF", n, err)
				}
				return
			}
			if n != tt.n || !errors.Is(err, tt.err) && err != tt.err {
				t.Fatalf("n=%d err=%v want n=%d err=%v", n, err, tt.n, tt.err)
			}
		})
	}
}

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
