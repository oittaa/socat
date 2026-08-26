package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestWrapCommonSkipsLateOptionsWithoutSocketFD(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WrapCommon(spec, relay.NetStream{Conn: a}); err != nil {
		t.Fatalf("WrapCommon on net.Pipe: %v", err)
	}
}
