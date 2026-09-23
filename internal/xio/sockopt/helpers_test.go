package sockopt_test

import (
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func decodeAddress(spec parse.Spec) (addrconfig.Address, error) {
	prepared, err := xio.PrepareSpec(spec)
	if err == nil {
		return prepared.Config, nil
	}
	config, err2 := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type})
	if err2 != nil {
		return addrconfig.Address{}, err
	}
	return config, nil
}

func mustDecodeAddress(t *testing.T, spec parse.Spec) addrconfig.Address {
	t.Helper()
	config, err := decodeAddress(spec)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

type stubPacketConn struct{}

func (stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (stubPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (stubPacketConn) Close() error                           { return nil }
func (stubPacketConn) LocalAddr() net.Addr                    { return nil }
func (stubPacketConn) SetDeadline(time.Time) error            { return nil }
func (stubPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (stubPacketConn) SetWriteDeadline(time.Time) error       { return nil }
