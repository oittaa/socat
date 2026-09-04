package xio

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestSetupStreamRejectsLifecycleWithoutDescriptor(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,append")
	if err != nil {
		t.Fatal(err)
	}
	_, err = SetupStream(spec, relay.NetStream{Conn: a})
	if err == nil || !strings.Contains(err.Error(), "does not expose a descriptor") {
		t.Fatalf("error=%v want stream does not expose a descriptor", err)
	}
}

func TestSetupStreamSkipsLateOptionsWithoutSocketFD(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetupStream(spec, relay.NetStream{Conn: a}); err != nil {
		t.Fatalf("SetupStream on net.Pipe: %v", err)
	}
}

type stubPacketConn struct{}

func (stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (stubPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (stubPacketConn) Close() error                           { return nil }
func (stubPacketConn) LocalAddr() net.Addr                    { return nil }
func (stubPacketConn) SetDeadline(time.Time) error            { return nil }
func (stubPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (stubPacketConn) SetWriteDeadline(time.Time) error       { return nil }

func TestApplyLateSocketOptionsToPacketConnRejectsNonSocket(t *testing.T) {
	spec, err := parse.ParseSpec("QUIC-LISTEN:0,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyLateSocketOptionsToPacketConn(stubPacketConn{}, spec)
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want packet connection does not expose a socket", err)
	}
}

func TestApplyFDLifecycleToPacketConnRejectsNonSocket(t *testing.T) {
	spec, err := parse.ParseSpec("QUIC-LISTEN:0,append")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyFDLifecycleToPacketConn(stubPacketConn{}, spec)
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want packet connection does not expose a socket", err)
	}
}

func TestApplyIPSendOptsToPacketConnRejectsNonSocket(t *testing.T) {
	spec, err := parse.ParseSpec("QUIC:127.0.0.1:1,ip-ttl=9")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyIPSendOptsToPacketConn(stubPacketConn{}, spec, "udp4")
	if err == nil || !strings.Contains(err.Error(), "does not expose a socket") {
		t.Fatalf("error=%v want packet connection does not expose a socket", err)
	}
}
