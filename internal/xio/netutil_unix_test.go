//go:build linux

package xio

import (
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func tcpPairForKeepalive(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	cli, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv := (<-ch)
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	t.Cleanup(func() { _ = srv.c.Close() })
	return cli
}

func TestApplyKeepAliveConfigErrors(t *testing.T) {
	cases := []struct{ spec, want string }{
		{"TCP4:127.0.0.1:1,keepidle=nope", "keepidle"},
		{"TCP4:127.0.0.1:1,keepidle=-5s", "positive"},
		{"TCP4:127.0.0.1:1,keepcnt=-1", "keepcnt"},
		{"TCP4:127.0.0.1:1,keepcnt=0", "keepcnt"},
	}
	for _, tc := range cases {
		spec, err := parse.ParseSpec(tc.spec)
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		tc2 := tcpPairForKeepalive(t)
		err = ApplyTCPConnOpts(spec, tc2)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err=%v want containing %q", tc.spec, err, tc.want)
		}
	}
}

func TestApplyKeepAliveExplicitDisableWins(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,keepidle=7s,keepalive=0")
	if err != nil {
		t.Fatal(err)
	}
	tc := tcpPairForKeepalive(t)
	// Explicit keepalive=0 must win over sub-options; net.TCPConn exposes no
	// getter, so success here means the config path accepted the precedence.
	if err := ApplyTCPConnOpts(spec, tc); err != nil {
		t.Fatalf("explicit disable: %v", err)
	}
}

func TestApplyListenBacklogUnix(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := ApplyListenBacklog(ln, 3); err != nil {
		t.Fatal(err)
	}
}
