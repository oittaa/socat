package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseVsockCIDEmptyIsAny(t *testing.T) {
	t.Parallel()
	cid, err := parseVsockCID("")
	if err != nil {
		t.Fatal(err)
	}
	if cid != vsockCIDAny {
		t.Fatalf("empty cid=%d want ANY", cid)
	}
}

func TestParseVsockConnectParams(t *testing.T) {
	t.Parallel()
	s, err := parse.ParseSpec("VSOCK-CONNECT:1:0x22")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := parseVsockConnectParams(mustAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if ep.cid != 1 || ep.port != 0x22 {
		t.Fatalf("got %+v", ep)
	}
	if _, err := parseVsockConnectParams(mustAddr(t, parse.Spec{Type: "VSOCK-CONNECT", Params: []string{"1"}})); err == nil {
		t.Fatal("expected error for missing port")
	}
}
