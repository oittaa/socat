package xio

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

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
	}{
		{"tcp4", "", "0.0.0.0"},
		{"udp4", "", "0.0.0.0"},
		{"ip4", "", "0.0.0.0"},
		{"tcp6", "", "::"},
		{"udp6", "", "::"},
		{"tcp", "", "::"},
		{"tcp4", "127.0.0.1", "127.0.0.1"},
		{"tcp6", "[::1]", "[::1]"},
		// Explicit IPv6 wildcard on a v4-forced network falls back to v4.
		{"tcp4", "::", "0.0.0.0"},
		{"tcp4", "[::]", "0.0.0.0"},
		{"udp4", "::", "0.0.0.0"},
		{"ip4", "::", "0.0.0.0"},
		{"sctp4", "::", "0.0.0.0"},
		{"sctp4", "", "0.0.0.0"},
		{"tcp6", "::", "::"},
	}
	for _, tc := range cases {
		if got := ListenBindHost(tc.network, tc.bind); got != tc.want {
			t.Errorf("ListenBindHost(%q, %q) = %q, want %q", tc.network, tc.bind, got, tc.want)
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
