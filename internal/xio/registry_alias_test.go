package xio_test

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestDirectRegistrationBeatsClassicAlias(t *testing.T) {
	reg, ok := xio.AddressRegistrationForType("TCP-L")
	if !ok || reg.Name != "TCP-L" {
		t.Fatalf("TCP-L=%+v ok=%v; direct RegisterAddress must win over TCP-LISTEN alias", reg, ok)
	}
	reg, ok = xio.AddressRegistrationForType("ACCEPT")
	if !ok || reg.Name != "ACCEPT" {
		t.Fatalf("ACCEPT=%+v ok=%v; direct RegisterAddress must win over ACCEPT-FD alias", reg, ok)
	}
}

func TestUnsupportedFamilyAliasesRemainUnknown(t *testing.T) {
	for _, name := range []string{
		"DCCP", "DCCP-CONNECT", "DCCP-L", "DCCP-LISTEN",
		"DCCP4", "DCCP4-CONNECT", "DCCP4-L", "DCCP4-LISTEN",
		"DCCP6", "DCCP6-CONNECT", "DCCP6-L", "DCCP6-LISTEN",
		"READLINE", "UDPLITE", "UDPLITE4-LISTEN", "UDPLITE6-DGRAM",
	} {
		if _, ok := xio.AddressRegistrationForType(name); ok {
			t.Errorf("%s must remain unknown", name)
		}
		_, err := xio.OpenSpec(context.Background(), parse.Spec{Type: name}, xio.ModeRDWR, nil)
		if err == nil || !strings.Contains(err.Error(), "unknown device/address") {
			t.Errorf("%s OpenSpec err=%v want unknown device/address", name, err)
		}
	}
}

func TestParserShorthandDashStaysOutOfRegistry(t *testing.T) {
	if _, ok := xio.AddressRegistrationForType("-"); ok {
		t.Fatal("parser shorthand - must not resolve in the address registry")
	}
	ch, err := parse.ParseChannel("-")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single == nil || ch.Single.Type != "STDIO" {
		t.Fatalf("ParseChannel(-)=%+v want STDIO", ch.Single)
	}
	if _, ok := xio.AddressRegistrationForType("STDIO"); !ok {
		t.Fatal("STDIO opener missing")
	}
}

func TestTUNAndINTERFACEHaveDistinctKinds(t *testing.T) {
	tun, ok := xio.AddressRegistrationForType("TUN")
	if !ok || tun.Kind != addrconfig.AddressKindTUN {
		t.Fatalf("TUN kind=%v ok=%v", tun.Kind, ok)
	}
	iface, ok := xio.AddressRegistrationForType("INTERFACE")
	if !ok || iface.Kind != addrconfig.AddressKindINTERFACE {
		t.Fatalf("INTERFACE kind=%v ok=%v", iface.Kind, ok)
	}
	alias, ok := xio.AddressRegistrationForType("IF")
	if !ok || alias.Kind != iface.Kind || alias.Name != "INTERFACE" {
		t.Fatalf("IF=%+v ok=%v", alias, ok)
	}
}

func TestFallbackAliasOpenSpecIsNotUnknown(t *testing.T) {
	_, err := xio.OpenSpec(context.Background(), parse.Spec{Type: "INET"}, xio.ModeRDWR, nil)
	if err == nil {
		t.Fatal("INET with no host/port unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("INET should resolve to TCP-CONNECT: %v", err)
	}
}
