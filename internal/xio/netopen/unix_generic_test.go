package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestGenericUnixClientUsesKindAndRole(t *testing.T) {
	if !genericUnixClient(addrconfig.Address{Facts: addrconfig.Facts{Kind: addrconfig.AddressKindUNIX}}) {
		t.Fatal("UNIX Role Other")
	}
	if !genericUnixClient(addrconfig.Address{Facts: addrconfig.Facts{Kind: addrconfig.AddressKindABSTRACT}}) {
		t.Fatal("ABSTRACT-CLIENT Role Other")
	}
	if genericUnixClient(addrconfig.Address{Facts: addrconfig.Facts{Kind: addrconfig.AddressKindUNIX, Role: addrconfig.AddressRoleConnect}}) {
		t.Fatal("UNIX-CONNECT")
	}
	if genericUnixClient(addrconfig.Address{Type: "UNIX"}) {
		t.Fatal("Type string without Kind must not match")
	}
}
