package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestPrepareSpecUnknownOptionBeforeUnknownDevice(t *testing.T) {
	_, err := xio.PrepareSpec(parse.Spec{Type: "FOO", Params: []string{"x"}, Options: []parse.Option{{Name: "unknownopt"}}})
	if err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Fatalf("err=%v want unknown option", err)
	}
	_, err = xio.PrepareSpec(parse.Spec{Type: "FOO", Params: []string{"x"}, Options: []parse.Option{{Name: "nodelay"}}})
	if err == nil || !strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("err=%v want unknown device/address", err)
	}
}

func TestPrepareSpecRetainsDecodedFDAndHostPort(t *testing.T) {
	fd, err := xio.PrepareSpec(mustParseSpec(t, "FD:0x20"))
	if err != nil {
		t.Fatal(err)
	}
	if !fd.Config.File.FDSet || fd.Config.File.FD != 32 {
		t.Fatalf("FD=%+v", fd.Config.File)
	}

	tcp, err := xio.PrepareSpec(mustParseSpec(t, "TCP4:127.0.0.1:080"))
	if err != nil {
		t.Fatal(err)
	}
	if tcp.Config.Facts.Family != addrconfig.IPFamilyIPv4 || tcp.Config.Network.IPFamily != addrconfig.IPFamilyIPv4 {
		t.Fatalf("family=%+v", tcp.Config)
	}
	if !tcp.Config.Network.Target.IsLiteral() || tcp.Config.Network.TargetPort.Number != 80 {
		t.Fatalf("target=%+v port=%+v", tcp.Config.Network.Target, tcp.Config.Network.TargetPort)
	}
}

func TestPrepareSpecDecodesRangeAndResNSAddr(t *testing.T) {
	prepared, err := xio.PrepareSpec(mustParseSpec(t, "TCP4-LISTEN:0,range=127.0.0.0/8,res-nsaddr=127.0.0.1:5353"))
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Config.Network.RangeSet || prepared.Config.Network.Range.Form != addrconfig.RangeCIDR {
		t.Fatalf("range=%+v", prepared.Config.Network.Range)
	}
	if !prepared.Config.Common.NameServer.Set || prepared.Config.Common.NameServer.Port.Number != 5353 {
		t.Fatalf("ns=%+v", prepared.Config.Common.NameServer)
	}
}

func TestPrepareSpecRetainsPROXYEndpoints(t *testing.T) {
	prepared, err := xio.PrepareSpec(mustParseSpec(t, "PROXY:proxy.test:target.test:443,proxyport=080"))
	if err != nil {
		t.Fatal(err)
	}
	p := prepared.Config.Proxy
	if !p.EndpointsSet || p.Server.Name != "proxy.test" || p.Target.Name != "target.test" ||
		p.TargetPort.Number != 443 || !p.PortSet || p.Port.Number != 80 {
		t.Fatalf("proxy=%+v", p)
	}
}

func mustParseSpec(t *testing.T, text string) parse.Spec {
	t.Helper()
	spec, err := parse.ParseSpec(text)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
