//go:build linux || darwin

package xio

import (
	"net"
	"sync"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

type sockoptCall struct {
	level, opt, value int
}

type sockoptLog struct {
	mu    sync.Mutex
	calls []sockoptCall
}

func collectSetSockopt(t *testing.T) *sockoptLog {
	t.Helper()
	log := &sockoptLog{}
	restore := SetSockoptTestHook(func(call SockoptCall) {
		if !call.AsInt {
			return
		}
		log.mu.Lock()
		log.calls = append(log.calls, sockoptCall{level: call.Level, opt: call.Opt, value: call.IntValue})
		log.mu.Unlock()
	})
	t.Cleanup(restore)
	return log
}

func (s *sockoptLog) snapshot() []sockoptCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sockoptCall(nil), s.calls...)
}

func countLevelOpt(calls []sockoptCall, level, opt int) int {
	n := 0
	for _, c := range calls {
		if c.level == level && c.opt == opt {
			n++
		}
	}
	return n
}

func TestQUICClientListenControlIPTTLSetsockoptOnce(t *testing.T) {
	spec, err := parse.ParseSpec("QUIC:127.0.0.1:1,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	calls := collectSetSockopt(t)
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	n := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if n != 1 {
		t.Fatalf("IP_TTL setsockopt count after QUIC client ListenControl=%d want 1", n)
	}
}

func TestQUICListenerListenControlIPTTLSetsockoptOnce(t *testing.T) {
	spec, err := parse.ParseSpec("QUIC-LISTEN:0,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	calls := collectSetSockopt(t)
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	n := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if n != 1 {
		t.Fatalf("IP_TTL setsockopt count after QUIC listener ListenControl=%d want 1", n)
	}
}

func TestApplyIPSendOptsInvalidThenValidFails(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-ttl=256,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	calls := collectSetSockopt(t)
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err == nil {
		t.Cleanup(func() { _ = pc.Close() })
		t.Fatal("ip-ttl=256 then ip-ttl=64 succeeded; classic fails on the first kernel-invalid value")
	}
	n := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if n != 1 {
		t.Fatalf("IP_TTL setsockopt count=%d want 1 (stop after invalid 256)", n)
	}
}

func TestIPOptionsInvalidThenValidFails(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-options=xzz,ip-options=x01")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err == nil {
		t.Cleanup(func() { _ = pc.Close() })
		t.Fatal("invalid earlier ip-options succeeded; classic stops on the first occurrence")
	}
}
