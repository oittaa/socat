package netopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestVsockEmptyCIDIsAny(t *testing.T) {
	t.Parallel()
	config := mustAddr(t, parse.Spec{Type: "VSOCK-CONNECT", Params: []string{"", "22"}})
	if !config.Network.VSOCKConnectSet || config.Network.VSOCKConnect.CID != vsockCIDAny {
		t.Fatalf("empty cid=%+v want ANY", config.Network.VSOCKConnect)
	}
}

func TestVsockConnectParams(t *testing.T) {
	t.Parallel()
	s, err := parse.ParseSpec("VSOCK-CONNECT:1:0x22")
	if err != nil {
		t.Fatal(err)
	}
	config := mustAddr(t, s)
	if !config.Network.VSOCKConnectSet || config.Network.VSOCKConnect.CID != 1 || config.Network.VSOCKConnect.Port != 0x22 {
		t.Fatalf("got %+v", config.Network.VSOCKConnect)
	}
	_, err = xio.PrepareSpec(parse.Spec{Type: "VSOCK-CONNECT", Params: []string{"1"}})
	if err == nil || !strings.Contains(err.Error(), "wrong number of parameters (1 instead of 2)") {
		t.Fatalf("missing port: %v", err)
	}
}

func TestVsockListenMinusOneIsAny(t *testing.T) {
	t.Parallel()
	config, err := addrconfig.Decode(parse.Spec{Type: "VSOCK-LISTEN", Params: []string{"-1"}}, addrconfig.Facts{
		Type:  "VSOCK-LISTEN",
		Group: "VSOCK (Linux)",
		Kind:  addrconfig.AddressKindVSOCK,
		Role:  addrconfig.AddressRoleListen,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !config.Network.VSOCKListenSet || config.Network.VSOCKListen != vsockPortAny {
		t.Fatalf("listen=%+v want ANY", config.Network)
	}
}
