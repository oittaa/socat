package xio_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// classicFallbackAliases are classic addressnames[] spellings whose canonical
// Go opener is registered but the alias itself is not a RegisterAddress
// entry. Resolution is central in xio (PR C). Direct registrations such as
// TCP-L are omitted. Classic baseline: tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a.
var classicFallbackAliases = map[string]string{
	"ABSTRACT":     "ABSTRACT-CLIENT",
	"DATAGRAM":     "SOCKET-DATAGRAM",
	"DGRAM":        "SOCKET-DATAGRAM",
	"IF":           "INTERFACE",
	"INET":         "TCP-CONNECT",
	"INET-L":       "TCP-LISTEN",
	"INET-LISTEN":  "TCP-LISTEN",
	"INET4":        "TCP4-CONNECT",
	"INET4-L":      "TCP4-LISTEN",
	"INET4-LISTEN": "TCP4-LISTEN",
	"INET6":        "TCP6-CONNECT",
	"INET6-L":      "TCP6-LISTEN",
	"INET6-LISTEN": "TCP6-LISTEN",
	"IP-DGRAM":     "IP-DATAGRAM",
	"IP-SEND":      "IP-SENDTO",
	"IP4-DGRAM":    "IP4-DATAGRAM",
	"IP4-SEND":     "IP4-SENDTO",
	"IP6-DGRAM":    "IP6-DATAGRAM",
	"IP6-SEND":     "IP6-SENDTO",
	"LOCAL":        "UNIX-CONNECT",
	"SENDTO":       "SOCKET-SENDTO",
	"SOCKS":        "SOCKS4",
	"UDP-DGRAM":    "UDP-DATAGRAM",
	"UDP4-DGRAM":   "UDP4-DATAGRAM",
	"UDP6-DGRAM":   "UDP6-DATAGRAM",
	"UNIX-SEND":    "UNIX-SENDTO",
}

func TestClassicFallbackAliasesResolveToCanonical(t *testing.T) {
	direct := map[string]bool{}
	for _, r := range xio.AddressRegistrations() {
		direct[r.Name] = true
	}
	got := map[string]string{}
	for alias, dest := range xio.ClassicAddressAliases {
		if alias == "-" || alias == dest || direct[alias] {
			continue
		}
		reg, ok := xio.AddressRegistrationForType(alias)
		if !ok {
			continue
		}
		got[alias] = dest
		canon, canonOK := xio.AddressRegistrationForType(dest)
		if !canonOK {
			t.Errorf("%s resolved but canonical %s is unregistered", alias, dest)
			continue
		}
		if reg.Name != dest {
			t.Errorf("%s Name=%q want %q", alias, reg.Name, dest)
		}
		if reg.Group != canon.Group {
			t.Errorf("%s Group=%q want %q", alias, reg.Group, canon.Group)
		}
		if reg.Enabled != canon.Enabled {
			t.Errorf("%s Enabled=%v want %v (canonical %s)", alias, reg.Enabled, canon.Enabled, dest)
		}
		if !reflect.DeepEqual(reg.OptionCaps, canon.OptionCaps) {
			t.Errorf("%s OptionCaps=%v want %v", alias, reg.OptionCaps, canon.OptionCaps)
		}
	}
	if !reflect.DeepEqual(got, classicFallbackAliases) {
		t.Errorf("fallback aliases=%v want %v", got, classicFallbackAliases)
	}
	if len(got) != 26 {
		t.Errorf("fallback aliases=%d want 26", len(got))
	}
}

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
		"DTLS", "READLINE", "UDPLITE", "UDPLITE4-LISTEN", "UDPLITE6-DGRAM",
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

func TestAcceptFDIsRegistered(t *testing.T) {
	for _, name := range []string{"ACCEPT-FD", "ACCEPT"} {
		reg, ok := xio.AddressRegistrationForType(name)
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if name == "ACCEPT-FD" && reg.Name != "ACCEPT-FD" {
			t.Fatalf("ACCEPT-FD Name=%q", reg.Name)
		}
		if name == "ACCEPT" && reg.Name != "ACCEPT" {
			t.Fatalf("ACCEPT direct registration must win, Name=%q", reg.Name)
		}
		_, err := xio.OpenSpec(context.Background(), parse.Spec{Type: name}, xio.ModeRDWR, nil)
		if err == nil || strings.Contains(err.Error(), "unknown device/address") {
			t.Errorf("%s OpenSpec err=%v want registered opener error", name, err)
		}
	}
	canon, ok := xio.AddressRegistrationForType("ACCEPT-FD")
	if !ok {
		t.Fatal("ACCEPT-FD missing")
	}
	alias, ok := xio.AddressRegistrationForType("ACCEPT")
	if !ok {
		t.Fatal("ACCEPT missing")
	}
	if !reflect.DeepEqual(canon.OptionCaps, alias.OptionCaps) {
		t.Fatalf("ACCEPT OptionCaps=%v want %v", alias.OptionCaps, canon.OptionCaps)
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

func TestFallbackAliasOpenSpecIsNotUnknown(t *testing.T) {
	_, err := xio.OpenSpec(context.Background(), parse.Spec{Type: "INET"}, xio.ModeRDWR, nil)
	if err == nil {
		t.Fatal("INET with no host/port unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("INET should resolve to TCP-CONNECT: %v", err)
	}
}
