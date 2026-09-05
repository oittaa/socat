package cli

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnsupportedAddressFamiliesStayUnregistered(t *testing.T) {
	for _, name := range []string{
		"DCCP", "DCCP-CONNECT", "DCCP-L", "DCCP-LISTEN",
		"DCCP4", "DCCP4-CONNECT", "DCCP4-L", "DCCP4-LISTEN",
		"DCCP6", "DCCP6-CONNECT", "DCCP6-L", "DCCP6-LISTEN",
		"UDPLITE", "UDPLITE-CONNECT", "UDPLITE-LISTEN", "UDPLITE4-LISTEN", "UDPLITE6-DGRAM",
		"READLINE",
	} {
		if _, ok := xio.AddressRegistrationForType(name); ok {
			t.Errorf("%s must stay unregistered", name)
		}
	}
}

func TestNativeAddressesAndAliasesResolve(t *testing.T) {
	for _, name := range []string{
		"STDIO", "TCP", "TCP-CONNECT", "TCP-L", "TCP-LISTEN",
		"DTLS", "DTLS-CONNECT", "OPENSSL-DTLS-CLIENT", "OPENSSL-DTLS-LISTEN",
		"ABSTRACT", "ACCEPT-FD", "ACCEPT", "INET", "OPENSSL",
	} {
		if _, ok := xio.AddressRegistrationForType(name); !ok {
			t.Errorf("%s must resolve", name)
		}
	}
}

func TestParserStdioShorthand(t *testing.T) {
	s, err := parse.ParseSpec("-")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(s.Type, "STDIO") {
		t.Fatalf("-=%q want STDIO", s.Type)
	}
	if _, ok := xio.AddressRegistrationForType("-"); ok {
		t.Fatal("parser shorthand - must not be an address registry key")
	}
}
