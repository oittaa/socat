package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestFirstAvailableLowportRetriesOnlyAddressInUse(t *testing.T) {
	var tried []int
	port, err := firstAvailableLowportFrom(LowportMax, func(port int) error {
		tried = append(tried, port)
		if len(tried) < 3 {
			return syscall.EADDRINUSE
		}
		return nil
	})
	if err != nil || port != LowportMax-2 {
		t.Fatalf("port=%d err=%v", port, err)
	}
	if len(tried) != 3 {
		t.Fatalf("tried %v, want three ports", tried)
	}

	wantErr := errors.New("permission denied")
	tried = nil
	if _, err := firstAvailableLowportFrom(LowportMax, func(port int) error {
		tried = append(tried, port)
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("error=%v want %v", err, wantErr)
	}
	if len(tried) != 1 {
		t.Fatalf("non-EADDRINUSE tried %d ports, want 1", len(tried))
	}
}

func TestFirstAvailableLowportFromWrapsDownward(t *testing.T) {
	var tried []int
	port, err := firstAvailableLowportFrom(LowportMin, func(port int) error {
		tried = append(tried, port)
		if port != LowportMax {
			return syscall.EADDRINUSE
		}
		return nil
	})
	if err != nil || port != LowportMax {
		t.Fatalf("port=%d err=%v", port, err)
	}
	if len(tried) != 2 || tried[0] != LowportMin || tried[1] != LowportMax {
		t.Fatalf("tried %v, want [%d %d]", tried, LowportMin, LowportMax)
	}
}

func TestFirstAvailableLowportFromTriesFullRangeOnce(t *testing.T) {
	const start = 800
	var tried []int
	_, err := firstAvailableLowportFrom(start, func(port int) error {
		tried = append(tried, port)
		return syscall.EADDRINUSE
	})
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("err=%v want EADDRINUSE", err)
	}
	n := LowportMax - LowportMin + 1
	if len(tried) != n {
		t.Fatalf("tried %d ports, want %d", len(tried), n)
	}
	if tried[0] != start {
		t.Fatalf("first port %d, want start %d", tried[0], start)
	}
	seen := make(map[int]int, n)
	for i, p := range tried {
		if p < LowportMin || p > LowportMax {
			t.Fatalf("out of range port %d", p)
		}
		seen[p]++
		if i == 0 {
			continue
		}
		want := tried[i-1] - 1
		if tried[i-1] == LowportMin {
			want = LowportMax
		}
		if p != want {
			t.Fatalf("tried[%d]=%d, want %d after %d", i, p, want, tried[i-1])
		}
	}
	if len(seen) != n {
		t.Fatalf("unique ports %d, want %d", len(seen), n)
	}
	if tried[len(tried)-1] != start+1 {
		t.Fatalf("last port %d, want %d (wrap stop before retrying start)", tried[len(tried)-1], start+1)
	}
}

func TestFirstAvailableLowportFromStopsOnOtherErrorAfterWrap(t *testing.T) {
	wantErr := errors.New("permission denied")
	var tried []int
	_, err := firstAvailableLowportFrom(LowportMin, func(port int) error {
		tried = append(tried, port)
		if port == LowportMin {
			return syscall.EADDRINUSE
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v want %v", err, wantErr)
	}
	if len(tried) != 2 || tried[0] != LowportMin || tried[1] != LowportMax {
		t.Fatalf("tried %v, want [%d %d]", tried, LowportMin, LowportMax)
	}
}

func TestFirstAvailableLowportPicksPortInRange(t *testing.T) {
	port, err := FirstAvailableLowport(func(port int) error {
		if port < LowportMin || port > LowportMax {
			t.Fatalf("bind called with out of range port %d", port)
		}
		return nil
	})
	if err != nil || port < LowportMin || port > LowportMax {
		t.Fatalf("port=%d err=%v", port, err)
	}
}

func TestListenControlAppliesSetsockoptListen(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4-LISTEN:0,setsockopt-listen=%d:%d:1", solSocket, soReuseaddr))
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("valid pre-bind socket option: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	bad, err := parse.ParseSpec("TCP4-LISTEN:0,setsockopt-listen=-1:-1:1")
	if err != nil {
		t.Fatal(err)
	}
	lc = net.ListenConfig{Control: ListenControl(bad)}
	if ln, err = lc.Listen(context.Background(), "tcp4", "127.0.0.1:0"); err == nil {
		_ = ln.Close()
		t.Fatal("invalid pre-bind socket option unexpectedly succeeded")
	}
}

func TestListenBindHost(t *testing.T) {
	cases := []struct {
		network, bind, want string
		wantErr             bool
	}{
		{network: "tcp4", bind: "", want: "0.0.0.0"},
		{network: "udp4", bind: "", want: "0.0.0.0"},
		{network: "ip4", bind: "", want: "0.0.0.0"},
		{network: "sctp4", bind: "", want: "0.0.0.0"},
		{network: "tcp6", bind: "", want: "::"},
		{network: "udp6", bind: "", want: "::"},
		{network: "sctp6", bind: "", want: "::"},
		{network: "tcp", bind: "", want: "::"},
		{network: "tcp4", bind: "127.0.0.1", want: "127.0.0.1"},
		{network: "tcp6", bind: "[::1]", want: "[::1]"},
		{network: "tcp6", bind: "::", want: "::"},
		{network: "tcp", bind: "::", want: "::"},
		{network: "tcp4", bind: "::", wantErr: true},
		{network: "tcp4", bind: "[::]", wantErr: true},
		{network: "udp4", bind: "::", wantErr: true},
		{network: "udp4", bind: "[::]", wantErr: true},
		{network: "ip4", bind: "::", wantErr: true},
		{network: "sctp4", bind: "::", wantErr: true},
		{network: "tcp6", bind: "0.0.0.0", wantErr: true},
	}
	for _, tc := range cases {
		got, err := ListenBindHost(tc.network, tc.bind)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ListenBindHost(%q, %q) = %q, want error", tc.network, tc.bind, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ListenBindHost(%q, %q) = %q, %v, want %q", tc.network, tc.bind, got, err, tc.want)
		}
	}
}

func TestParsePositiveIntBase0AndTrailingJunk(t *testing.T) {
	n, err := ParsePositiveInt("0x10")
	if err != nil || n != 16 {
		t.Fatalf("0x10: n=%d err=%v want 16", n, err)
	}
	n, err = ParsePositiveInt("010")
	if err != nil || n != 8 {
		t.Fatalf("010: n=%d err=%v want 8", n, err)
	}
	if _, err := ParsePositiveInt("5abc"); err == nil {
		t.Fatal("5abc: expected error")
	}
	if _, err := ParsePositiveInt("0"); err == nil {
		t.Fatal("0: expected error")
	}
}

func TestParseIntAnyBase0(t *testing.T) {
	n, err := ParseIntAny("010")
	if err != nil || n != 8 {
		t.Fatalf("010: n=%d err=%v want 8", n, err)
	}
	n, err = ParseIntAny("0x10")
	if err != nil || n != 16 {
		t.Fatalf("0x10: n=%d err=%v want 16", n, err)
	}
	if _, err := ParseIntAny("10junk"); err == nil {
		t.Fatal("10junk: expected error")
	}
}

func TestParseSizeTMatchesUnsignedClassicParsing(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  uint64
	}{
		{value: "010", want: 8},
		{value: "0x10", want: 16},
		{value: "-1", want: ^uint64(0)},
	} {
		got, err := ParseSizeT(tc.value)
		if err != nil || got != tc.want {
			t.Errorf("ParseSizeT(%q)=%d,%v want %d", tc.value, got, err, tc.want)
		}
	}
	if _, err := ParseSizeT("10junk"); err == nil {
		t.Fatal("ParseSizeT accepted trailing junk")
	}
}

func TestReuseaddrListenDefault(t *testing.T) {
	udp, err := parse.ParseSpec("UDP4-LISTEN:1")
	if err != nil {
		t.Fatal(err)
	}
	if reuseaddrListenDefault(udp, "udp4") || reuseaddrListenDefault(udp, "udp") || reuseaddrListenDefault(udp, "udp6") {
		t.Fatal("UDP without fork must default SO_REUSEADDR off")
	}
	udpFork, err := parse.ParseSpec("UDP4-LISTEN:1,fork")
	if err != nil {
		t.Fatal(err)
	}
	if !reuseaddrListenDefault(udpFork, "udp4") {
		t.Fatal("UDP-LISTEN,fork must default SO_REUSEADDR on")
	}
	udpReuseOff, err := parse.ParseSpec("UDP4-LISTEN:1,fork,reuseaddr=0")
	if err != nil {
		t.Fatal(err)
	}
	// Default is on because of fork; ApplyReuse still honors reuseaddr=0.
	if !reuseaddrListenDefault(udpReuseOff, "udp4") {
		t.Fatal("fork still supplies the default; reuseaddr=0 is applied later")
	}
	tcp, err := parse.ParseSpec("TCP4-LISTEN:1")
	if err != nil {
		t.Fatal(err)
	}
	if !reuseaddrListenDefault(tcp, "tcp4") || !reuseaddrListenDefault(tcp, "tcp") {
		t.Fatal("TCP listen must default SO_REUSEADDR on")
	}
}

func TestRecvTimeoutFromSpecRejectsJunk(t *testing.T) {
	ok, err := parse.ParseSpec("UDP4-LISTEN:0,fork")
	if err != nil {
		t.Fatal(err)
	}
	d, err := RecvTimeoutFromSpec(ok)
	if err != nil || d != 0 {
		t.Fatalf("empty rcvtimeo d=%s err=%v", d, err)
	}
	bad, err := parse.ParseSpec("UDP4-LISTEN:0,fork,rcvtimeo=nope")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecvTimeoutFromSpec(bad); err == nil {
		t.Fatal("expected rcvtimeo parse error")
	}
}
