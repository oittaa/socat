//go:build linux || darwin

package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestQUICListenControlAppliesIPTTL(t *testing.T) {
	for _, raw := range []string{"QUIC:127.0.0.1:1,ip-ttl=37", "QUIC-LISTEN:0,ip-ttl=37"} {
		t.Run(raw, func(t *testing.T) {
			spec, err := parse.ParseSpec(raw)
			if err != nil {
				t.Fatal(err)
			}
			lc := net.ListenConfig{Control: ListenControl(mustDecodeAddress(t, spec))}
			pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			if got := udpLevelSockoptInt(t, pc.(*net.UDPConn), unix.IPPROTO_IP, unix.IP_TTL); got != 37 {
				t.Fatalf("IP_TTL=%d want 37", got)
			}
		})
	}
}

func TestApplyIPSendOptsInvalidThenValidFails(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-ttl=256,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(mustDecodeAddress(t, spec))}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err == nil {
		t.Cleanup(func() { _ = pc.Close() })
		t.Fatal("ip-ttl=256 then ip-ttl=64 succeeded; classic fails on the first kernel-invalid value")
	}
}

func TestIPOptionsInvalidThenValidFails(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-options=xzz,ip-options=x01")
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeAddress(spec)
	if err == nil {
		lc := net.ListenConfig{Control: ListenControl(config)}
		var pc net.PacketConn
		pc, err = lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
		if pc != nil {
			t.Cleanup(func() { _ = pc.Close() })
		}
	}
	if err == nil {
		t.Fatal("invalid earlier ip-options succeeded; classic stops on the first occurrence")
	}
}
