package xio

import (
	"reflect"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestOptionSupportedOnAddressClassicAndGoExtras(t *testing.T) {
	tcp := AddressRegistration{
		Name:       "TCP",
		Group:      GroupTCP,
		OptionCaps: ClassicAddressCaps("TCP"),
	}
	open := AddressRegistration{
		Name:       "OPEN",
		Group:      GroupFiles,
		OptionCaps: ClassicAddressCaps("OPEN"),
	}
	proxy := AddressRegistration{
		Name:       "PROXY",
		Group:      GroupProxy,
		OptionCaps: ClassicAddressCaps("PROXY"),
	}
	ws := AddressRegistration{
		Name:       "WS",
		Group:      GroupWebSocket,
		OptionCaps: ClassicAddressCaps("WS"),
	}

	if !OptionSupportedOnAddress(tcp, "append", nil, nil, nil) {
		t.Fatal("classic append (open|fd) must be allowed on TCP")
	}
	if OptionSupportedOnAddress(tcp, "pty", nil, nil, nil) {
		t.Fatal("pty must be rejected on TCP")
	}
	if OptionSupportedOnAddress(tcp, "echo", nil, nil, nil) {
		t.Fatal("echo must be rejected on TCP")
	}
	if !OptionSupportedOnAddress(tcp, "readbytes", nil, nil, nil) {
		t.Fatal("readbytes is GROUP_APPL")
	}
	if OptionSupportedOnAddress(open, "lowport", nil, nil, nil) {
		t.Fatal("lowport must be rejected on OPEN")
	}

	tlsTypes := []string{"TLS", "PROXY", "WSS", "QUIC"}
	tlsGroups := []string{GroupTLS, GroupWebSocket, GroupQUIC, GroupProxy}
	if !OptionSupportedOnAddress(proxy, "verify", tlsGroups, tlsTypes, nil) {
		t.Fatal("Go extra: verify on PROXY")
	}
	if OptionSupportedOnAddress(tcp, "verify", tlsGroups, tlsTypes, nil) {
		t.Fatal("verify must stay rejected on TCP")
	}
	wsReg := AddressRegistration{Name: "WS", Group: GroupWebSocket, OptionCaps: ClassicAddressCaps("WS")}
	if OptionSupportedOnAddress(wsReg, "cert", tlsGroups, tlsTypes, nil) {
		t.Fatal("cert must stay rejected on plain WS even though WSS shares the help section")
	}

	wsGroups := []string{GroupWebSocket}
	if !OptionSupportedOnAddress(ws, "path", wsGroups, nil, nil) {
		t.Fatal("Go extra: path on WS")
	}
	if OptionSupportedOnAddress(tcp, "path", wsGroups, nil, nil) {
		t.Fatal("path must be rejected on TCP")
	}

	reg := AddressRegistration{Name: "TCP-LISTEN-X", Group: GroupTCP, OptionCaps: DerivedOptionCaps("TCP-LISTEN-X", GroupTCP)}
	if !OptionCapsAllowed(reg.OptionCaps, []string{OptCapListen}) {
		t.Fatalf("fallback listen cap missing: %v", reg.OptionCaps)
	}
}

func TestClassicOptionGroupsForAliases(t *testing.T) {
	appendGroups, ok := ClassicOptionGroupsFor("o-append")
	if !ok || !reflect.DeepEqual(appendGroups, ClassicOptionGroups["append"]) {
		t.Fatalf("o-append groups=%v ok=%v", appendGroups, ok)
	}
	if parse.CanonicalOptionName("o-append") != "append" {
		t.Fatal("canonical o-append")
	}
	if parse.CanonicalOptionName("truncate") != "ftruncate" {
		t.Fatal("canonical truncate")
	}
	if parse.CanonicalOptionName("mode") != "perm" {
		t.Fatal("canonical mode")
	}
	if parse.CanonicalOptionName("uid") != "user" || parse.CanonicalOptionName("owner") != "user" {
		t.Fatal("canonical uid/owner")
	}
	if parse.CanonicalOptionName("gid") != "group" {
		t.Fatal("canonical gid")
	}
	if parse.CanonicalOptionName("ftruncate32") != "ftruncate" || parse.CanonicalOptionName("ftruncate64") != "ftruncate" {
		t.Fatal("canonical ftruncate32/64")
	}
	modeGroups, ok := ClassicOptionGroupsFor("mode")
	if !ok || !reflect.DeepEqual(modeGroups, ClassicOptionGroups["perm"]) {
		t.Fatalf("mode groups=%v ok=%v", modeGroups, ok)
	}
}
