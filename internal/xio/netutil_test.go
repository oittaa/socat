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
