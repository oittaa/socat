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
		{"tcp6", "::", "::"},
	}
	for _, tc := range cases {
		if got := ListenBindHost(tc.network, tc.bind); got != tc.want {
			t.Errorf("ListenBindHost(%q, %q) = %q, want %q", tc.network, tc.bind, got, tc.want)
		}
	}
}
