package addrconfig

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestDecodeINTERFACENameIsNotTUNPrefix(t *testing.T) {
	for _, text := range []string{"INTERFACE:lo", "IF:lo"} {
		spec, err := parse.ParseSpec(text)
		if err != nil {
			t.Fatal(err)
		}
		config, err := Decode(spec, Facts{Type: spec.Type, Group: "Linux TUN / INTERFACE", Kind: AddressKindINTERFACE})
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if config.Network.Kind != AddressKindINTERFACE {
			t.Fatalf("%s kind=%v want INTERFACE", text, config.Network.Kind)
		}
		if config.Network.TUNAddressSet {
			t.Fatalf("%s decoded %q as a TUN prefix", text, spec.Params)
		}
		if config.Network.InterfaceName != "lo" {
			t.Fatalf("%s interface=%q", text, config.Network.InterfaceName)
		}
	}
}

func TestDecodeINTERFACETypeFallbackWithoutKind(t *testing.T) {
	spec, err := parse.ParseSpec("INTERFACE:lo")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "INTERFACE", Group: "Linux TUN / INTERFACE"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Network.Kind != AddressKindOther {
		t.Fatalf("kind=%v want Other without registry Kind", config.Network.Kind)
	}
	if config.Network.TUNAddressSet {
		t.Fatal("must not treat INTERFACE as a TUN prefix")
	}
	if config.Network.InterfaceName != "" {
		t.Fatal("must not decode INTERFACE name without Kind")
	}
}

func TestDecodeTUNStillRequiresIPv4Prefix(t *testing.T) {
	spec, err := parse.ParseSpec("TUN:lo")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(spec, Facts{Type: "TUN", Group: "Linux TUN / INTERFACE", Kind: AddressKindTUN})
	if err == nil || !strings.Contains(err.Error(), "IPv4 required") {
		t.Fatalf("TUN:lo error=%v want IPv4 required", err)
	}
}

func TestDecodeTUNPrefix(t *testing.T) {
	spec, err := parse.ParseSpec("TUN:10.1.2.3/24")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "TUN", Group: "Linux TUN / INTERFACE", Kind: AddressKindTUN})
	if err != nil {
		t.Fatal(err)
	}
	if !config.Network.TUNAddressSet || config.Network.TUNAddress.String() != "10.1.2.3/24" {
		t.Fatalf("TUN prefix=%v set=%v", config.Network.TUNAddress, config.Network.TUNAddressSet)
	}
}
