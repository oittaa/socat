package addrconfig

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestDecodeUnsupportedTLSKeepsEarlierRejection(t *testing.T) {
	spec, err := parse.ParseSpec("TLS:127.0.0.1:1,fips=1,pseudo=1,pseudo=0")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "TLS"})
	if err != nil {
		t.Fatal(err)
	}
	if !config.TLS.UnsupportedSet || config.TLS.UnsupportedCanonical != "openssl-fips" {
		t.Fatalf("effective=%+v", config.TLS)
	}
	if config.TLS.UnsupportedName != "fips" {
		t.Fatalf("name=%q", config.TLS.UnsupportedName)
	}

	spec, err = parse.ParseSpec("TLS:127.0.0.1:1,method=SSLv23,fips=1,fips=0")
	if err != nil {
		t.Fatal(err)
	}
	config, err = Decode(spec, Facts{Type: "TLS"})
	if err != nil {
		t.Fatal(err)
	}
	if !config.TLS.UnsupportedSet || config.TLS.UnsupportedCanonical != "openssl-method" {
		t.Fatalf("method erased: set=%v can=%q", config.TLS.UnsupportedSet, config.TLS.UnsupportedCanonical)
	}
}

func TestDecodeIffLastWinsClearsOppositeMask(t *testing.T) {
	spec, err := parse.ParseSpec("TUN,iff-up=0,iff-up=1")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "TUN", Kind: AddressKindTUN})
	if err != nil {
		t.Fatal(err)
	}
	const iffUp = 0x1
	if config.Network.TUNInterfaceSet&iffUp == 0 {
		t.Fatal("iff-up=1 last must remain in the set mask")
	}
	if config.Network.TUNInterfaceClr&iffUp != 0 {
		t.Fatal("iff-up=1 last must leave the clear mask")
	}

	spec, err = parse.ParseSpec("TUN,iff-up=1,iff-up=0")
	if err != nil {
		t.Fatal(err)
	}
	config, err = Decode(spec, Facts{Type: "TUN", Kind: AddressKindTUN})
	if err != nil {
		t.Fatal(err)
	}
	if config.Network.TUNInterfaceClr&iffUp == 0 {
		t.Fatal("iff-up=0 last must remain in the clear mask")
	}
	if config.Network.TUNInterfaceSet&iffUp != 0 {
		t.Fatal("iff-up=0 last must leave the set mask")
	}
}

func TestDecodeTLSVersionRangeAfterLastWins(t *testing.T) {
	_, err := Decode(mustParseSpec(t, "TLS:h:1,min-version=TLS1.3,max-version=TLS1.2,max-version=TLS1.3"), Facts{Type: "TLS"})
	if err != nil {
		t.Fatalf("last max-version must accept the range: %v", err)
	}
	_, err = Decode(mustParseSpec(t, "TLS:h:1,min-version=TLS1.3,min-version=TLS1.2,max-version=TLS1.2"), Facts{Type: "TLS"})
	if err != nil {
		t.Fatalf("last min-version must accept the range: %v", err)
	}
	_, err = Decode(mustParseSpec(t, "TLS:h:1,min-version=TLS1.3,max-version=TLS1.2"), Facts{Type: "TLS"})
	if err == nil || !strings.Contains(err.Error(), "minimum TLS protocol version exceeds maximum") {
		t.Fatalf("final invalid range: %v", err)
	}
	_, err = Decode(mustParseSpec(t, "TLS:h:1,min-version=DTLS1.2,min-version=TLS1.2"), Facts{Type: "TLS"})
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
		t.Fatalf("invalid earlier min-version: %v", err)
	}
}

func TestDecodeCrorlfDisableAndLastActiveConversion(t *testing.T) {
	got := decodeSpec(t, "TCP:host:9,crorlf,crorlf=0")
	if got.Transfer.LineEnding != LineEndingRaw {
		t.Fatalf("crorlf,crorlf=0 ending=%v", got.Transfer.LineEnding)
	}
	got = decodeSpec(t, "TCP:host:9,cr,crorlf,crorlf=0")
	if got.Transfer.LineEnding != LineEndingCR {
		t.Fatalf("cr then disabled crorlf ending=%v", got.Transfer.LineEnding)
	}
	got = decodeSpec(t, "TCP:host:9,crnl,crorlf=0")
	if got.Transfer.LineEnding != LineEndingCRNL {
		t.Fatalf("crnl then disabled crorlf ending=%v", got.Transfer.LineEnding)
	}
	got = decodeSpec(t, "TCP:host:9,crorlf,cr")
	if got.Transfer.LineEnding != LineEndingCR {
		t.Fatalf("crorlf then cr ending=%v", got.Transfer.LineEnding)
	}
}

func TestDecodeB0IsRecognizedBaud(t *testing.T) {
	spec, err := parse.ParseSpec("PTY,b0")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(spec, Facts{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Terminal.Actions) != 1 || config.Terminal.Actions[0].Kind != TerminalActionSpeed ||
		config.Terminal.Actions[0].Value != 0 || config.Terminal.Actions[0].Name != "b0" {
		t.Fatalf("b0 actions=%+v", config.Terminal.Actions)
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
