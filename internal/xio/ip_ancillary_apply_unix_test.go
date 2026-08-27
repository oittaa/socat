//go:build unix

package xio

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
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

func ipTTLTosSeq(calls []sockoptCall) []string {
	var seq []string
	for _, c := range calls {
		switch {
		case c.level == unix.IPPROTO_IP && c.opt == unix.IP_TOS:
			seq = append(seq, "ip-tos")
		case c.level == unix.IPPROTO_IP && c.opt == unix.IP_TTL:
			seq = append(seq, "ip-ttl")
		}
	}
	return seq
}

func TestTCPConnectIPTTLSetsockoptOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accept := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accept <- nil
			return
		}
		accept <- c
	}()
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	calls := collectSetSockopt(t)
	d := &net.Dialer{Control: DialControl(spec, "tcp4", nil)}
	cli, err := d.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv := <-accept
	if srv == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = srv.Close() })
	afterDial := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if afterDial != 1 {
		t.Fatalf("IP_TTL setsockopt count after DialControl=%d want 1", afterDial)
	}
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	afterLate := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if afterLate != 1 {
		t.Fatalf("IP_TTL setsockopt count after ApplyTCPConnOpts=%d want 1 (no post-connect duplicate)", afterLate)
	}
}

func TestTCPListenIPTTLSetsockoptOnce(t *testing.T) {
	spec, err := parse.ParseSpec("TCP-LISTEN:0,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	calls := collectSetSockopt(t)
	lc := net.ListenConfig{Control: ListenControl(spec)}
	// Go 1.27 defaults Multipath TCP on listeners and falls back to TCP
	// after Control has already run; disable it so the count is one fd.
	lc.SetMultipathTCP(false)
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	afterListen := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if afterListen != 1 {
		t.Fatalf("IP_TTL setsockopt count after ListenControl=%d want 1", afterListen)
	}
	accept := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accept <- nil
			return
		}
		accept <- c
	}()
	cli, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv := <-accept
	if srv == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = srv.Close() })
	if err := ApplyTCPConnOpts(spec, srv); err != nil {
		t.Fatal(err)
	}
	afterAccept := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if afterAccept != 1 {
		t.Fatalf("IP_TTL setsockopt count after accept+ApplyTCPConnOpts=%d want 1", afterAccept)
	}
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

func TestApplyIPSendOptsCommandLineOrder(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want []string
	}{
		{spec: "UDP4:127.0.0.1:1,ip-tos=0x10,ip-ttl=64", want: []string{"ip-tos", "ip-ttl"}},
		{spec: "UDP4:127.0.0.1:1,ip-ttl=64,ip-tos=0x10", want: []string{"ip-ttl", "ip-tos"}},
		{spec: "UDP4:127.0.0.1:1,tos=0x10,ttl=64", want: []string{"ip-tos", "ip-ttl"}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
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
			got := ipTTLTosSeq(calls.snapshot())
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("setsockopt order=%v want %v", got, tc.want)
			}
		})
	}
}

func TestApplyIPSendOptsWalksEveryOccurrence(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ttl=7,ip-ttl=9")
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
	if n != 2 {
		t.Fatalf("IP_TTL setsockopt count=%d want 2 (ttl then ip-ttl)", n)
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		ttl, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if ttl != 9 {
		t.Fatalf("IP_TTL=%d want 9 (last occurrence at the kernel)", ttl)
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

func TestApplyAncillaryRecvOptsCommandLineOrder(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-pktinfo,ip-recvttl")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	calls := collectSetSockopt(t)
	raw, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = ApplyAncillaryRecvOpts(int(fd), spec)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	var seq []string
	for _, c := range calls.snapshot() {
		if c.level != unix.IPPROTO_IP {
			continue
		}
		switch c.opt {
		case unix.IP_PKTINFO:
			seq = append(seq, "ip-pktinfo")
		case unix.IP_RECVTTL:
			seq = append(seq, "ip-recvttl")
		}
	}
	want := "ip-pktinfo,ip-recvttl"
	if strings.Join(seq, ",") != want {
		t.Fatalf("recv setsockopt order=%v want %s", seq, want)
	}

	spec2, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recvttl,ippktinfo")
	if err != nil {
		t.Fatal(err)
	}
	pc2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc2.Close() })
	calls2 := collectSetSockopt(t)
	raw2, err := pc2.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw2.Control(func(fd uintptr) {
		optionErr = ApplyAncillaryRecvOpts(int(fd), spec2)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	seq = seq[:0]
	for _, c := range calls2.snapshot() {
		if c.level != unix.IPPROTO_IP {
			continue
		}
		switch c.opt {
		case unix.IP_PKTINFO:
			seq = append(seq, "ip-pktinfo")
		case unix.IP_RECVTTL:
			seq = append(seq, "ip-recvttl")
		}
	}
	want = "ip-recvttl,ip-pktinfo"
	if strings.Join(seq, ",") != want {
		t.Fatalf("recv alias order=%v want %s", seq, want)
	}
}

func TestUDPDialControlIPTTLSetsockoptOnce(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-ttl=64")
	if err != nil {
		t.Fatal(err)
	}
	calls := collectSetSockopt(t)
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", ln.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	n := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if n != 1 {
		t.Fatalf("IP_TTL setsockopt count after UDP DialControl=%d want 1", n)
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatalf("conn type %T", c)
	}
	if err := ApplyUDPConnOpts(uc, spec, "udp4"); err != nil {
		t.Fatal(err)
	}
	after := countLevelOpt(calls.snapshot(), unix.IPPROTO_IP, unix.IP_TTL)
	if after != 1 {
		t.Fatalf("IP_TTL setsockopt count after ApplyUDPConnOpts=%d want 1", after)
	}
}

func ipMixedRecvSendSeq(calls []sockoptCall) []string {
	var seq []string
	for _, c := range calls {
		if c.level != unix.IPPROTO_IP {
			continue
		}
		switch {
		case unix.IP_RECVTTL != unix.IP_TTL && c.opt == unix.IP_RECVTTL:
			seq = append(seq, "ip-recvttl")
		case c.opt == unix.IP_TTL:
			if unix.IP_TTL == unix.IP_RECVTTL && c.value == 1 {
				seq = append(seq, "ip-recvttl")
			} else {
				seq = append(seq, "ip-ttl")
			}
		}
	}
	return seq
}

func packetConnIPOptions(t *testing.T, pc net.PacketConn) []byte {
	t.Helper()
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("PacketConn type %T is not syscall.Conn", pc)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		got, gerr = sockoptIPOptions(int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return got
}

func TestPastSocketMixedRecvSendCommandLineOrder(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want []string
	}{
		{spec: "UDP4-RECV:0,ip-recvttl=1,ip-ttl=64", want: []string{"ip-recvttl", "ip-ttl"}},
		{spec: "UDP4-RECV:0,ip-ttl=64,ip-recvttl=1", want: []string{"ip-ttl", "ip-recvttl"}},
		{spec: "UDP4-RECV:0,recvttl=1,ttl=64", want: []string{"ip-recvttl", "ip-ttl"}},
		{spec: "UDP4-RECV:0,ttl=64,recvttl=1", want: []string{"ip-ttl", "ip-recvttl"}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			var recvTTLDuring, ttlDuring int
			calls := collectSetSockopt(t)
			lc := net.ListenConfig{
				Control: func(network, address string, c syscall.RawConn) error {
					if err := ListenControl(spec)(network, address, c); err != nil {
						return err
					}
					return c.Control(func(fd uintptr) {
						recvTTLDuring, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL)
						ttlDuring, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
					})
				},
			}
			pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			got := ipMixedRecvSendSeq(calls.snapshot())
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("setsockopt order=%v want %v (must be before bind)", got, tc.want)
			}
			if recvTTLDuring == 0 {
				t.Fatal("IP_RECVTTL unset during ListenControl; classic applies it at PH_PASTSOCKET before bind")
			}
			if ttlDuring != 64 {
				t.Fatalf("IP_TTL during ListenControl=%d want 64 (before bind)", ttlDuring)
			}
			uc, ok := pc.(*net.UDPConn)
			if !ok {
				t.Fatalf("PacketConn type %T", pc)
			}
			if err := ApplyUDPConnOpts(uc, spec, "udp4"); err != nil {
				t.Fatal(err)
			}
			after := ipMixedRecvSendSeq(calls.snapshot())
			if strings.Join(after, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("ApplyUDPConnOpts reapplied IP options: %v want %v", after, tc.want)
			}
		})
	}
}

func TestPastSocketNamedAndGenericCommandLineOrder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options string
		want    []int
	}{
		{
			name:    "named-then-generic",
			options: fmt.Sprintf("ip-ttl=64,setsockopt-socket=%d:%d:65", unix.IPPROTO_IP, unix.IP_TTL),
			want:    []int{64, 65},
		},
		{
			name:    "generic-then-named",
			options: fmt.Sprintf("setsockopt-socket=%d:%d:65,ip-ttl=64", unix.IPPROTO_IP, unix.IP_TTL),
			want:    []int{65, 64},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec("UDP4:127.0.0.1:1," + tc.options)
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

			var got []int
			for _, call := range calls.snapshot() {
				if call.level == unix.IPPROTO_IP && call.opt == unix.IP_TTL {
					got = append(got, call.value)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("IP_TTL values=%v want %v", got, tc.want)
			}
		})
	}
}

func TestIPOptionsOccurrencesAppend(t *testing.T) {
	// BSD kernels (including Darwin) reject IP_OPTIONS whose length is not a
	// multiple of 4. x01000000 is IPOPT_NOP plus padding; Linux accepts it too.
	const oneHex = "x01000000"
	const twoHex = "x01010000"
	probeIPOptionsAppend(t, oneHex)

	listen := func(specText string) net.PacketConn {
		t.Helper()
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		lc := net.ListenConfig{Control: ListenControl(spec)}
		pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		return pc
	}
	gotOne := packetConnIPOptions(t, listen("UDP4:127.0.0.1:1,ip-options="+oneHex))
	gotTwo := packetConnIPOptions(t, listen("UDP4:127.0.0.1:1,ip-options="+oneHex+",ip-options="+oneHex))
	if bytes.Equal(gotTwo, gotOne) {
		t.Fatalf("IP_OPTIONS=%x after two occurrences equals a single occurrence; classic OFUNC_SOCKOPT_APPEND concatenates", gotTwo)
	}
	want := ipOptionsAppendWant(t, gotOne, oneHex)
	if !bytes.Equal(gotTwo, want) {
		t.Fatalf("IP_OPTIONS=%x want %x (classic getsockopt+append+setsockopt)", gotTwo, want)
	}

	gotAlias := packetConnIPOptions(t, listen("UDP4:127.0.0.1:1,ipoptions="+oneHex+",ip-options="+twoHex))
	wantAlias := ipOptionsAppendWant(t, gotOne, twoHex)
	if !bytes.Equal(gotAlias, wantAlias) {
		t.Fatalf("alias mix IP_OPTIONS=%x want %x", gotAlias, wantAlias)
	}
}

func probeIPOptionsAppend(t *testing.T, hexOpt string) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	extra, err := ParseHexOpt(hexOpt)
	if err != nil {
		t.Fatal(err)
	}
	// Probe the kernel directly. Calling appendSockoptIPOptions here would
	// make a defect in the helper under test look like an unsupported kernel
	// and incorrectly skip the regression test.
	if err := unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(extra)); err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOPROTOOPT) {
			t.Skipf("IP_OPTIONS not usable on this kernel/socket: %v", err)
		}
		t.Fatal(err)
	}
}

func ipOptionsAppendWant(t *testing.T, existing []byte, hexOpt string) []byte {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	extra, err := ParseHexOpt(hexOpt)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append([]byte{}, existing...), extra...)
	if len(combined) > maxIPOptions {
		combined = combined[:maxIPOptions]
	}
	if err := unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(combined)); err != nil {
		t.Fatal(err)
	}
	want, err := sockoptIPOptions(fd)
	if err != nil {
		t.Fatal(err)
	}
	return want
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
