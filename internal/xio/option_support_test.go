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
		OptionCaps: CapsTCPConnect,
	}
	open := AddressRegistration{
		Name:       "OPEN",
		Group:      GroupFiles,
		OptionCaps: CapsOpen,
	}
	proxy := AddressRegistration{
		Name:       "PROXY",
		Group:      GroupProxy,
		OptionCaps: CapsProxy,
	}
	ws := AddressRegistration{
		Name:       "WS",
		Group:      GroupWebSocket,
		OptionCaps: CapsTCPConnect,
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
	wsReg := AddressRegistration{Name: "WS", Group: GroupWebSocket, OptionCaps: CapsTCPConnect}
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

	handshakeTypes := []string{
		"TLS", "TLS-CONNECT", "TLS-LISTEN", "OPENSSL", "WS", "WSS", "QUIC", "PROXY", "SOCKS5",
	}
	if !OptionSupportedOnAddress(proxy, "handshake-timeout", nil, handshakeTypes, nil) {
		t.Fatal("Go extra: handshake-timeout on PROXY")
	}
	if !OptionSupportedOnAddress(ws, "handshake-timeout", nil, handshakeTypes, nil) {
		t.Fatal("Go extra: handshake-timeout on WS")
	}
	if OptionSupportedOnAddress(tcp, "handshake-timeout", nil, handshakeTypes, nil) {
		t.Fatal("handshake-timeout must stay rejected on TCP")
	}
	if OptionSupportedOnAddress(open, "handshake-timeout", nil, handshakeTypes, nil) {
		t.Fatal("handshake-timeout must stay rejected on OPEN")
	}

	reg := AddressRegistration{Name: "TCP-LISTEN", Group: GroupTCP, OptionCaps: CapsTCPListen}
	if !OptionCapsAllowed(reg.OptionCaps, []string{OptCapListen}) {
		t.Fatalf("listen cap missing: %v", reg.OptionCaps)
	}
}

func TestTermiosOptionNames(t *testing.T) {
	names := TermiosOptionNames()
	have := make(map[string]bool, len(names))
	for _, name := range names {
		have[name] = true
	}
	for _, name := range []string{"vintr", "intr", "ispeed", "ospeed", "icanon", "echo", "sane", "b115200"} {
		if !have[name] {
			t.Errorf("TermiosOptionNames missing %q", name)
		}
	}
	if len(names) < 50 {
		t.Fatalf("TermiosOptionNames returned %d names, want a full termios set", len(names))
	}
}

func TestOptionCapsForAliases(t *testing.T) {
	appendGroups, ok := OptionCapsFor("o-append")
	if !ok || !reflect.DeepEqual(appendGroups, optionRequiredCaps["append"]) {
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
	modeGroups, ok := OptionCapsFor("mode")
	if !ok || !reflect.DeepEqual(modeGroups, optionRequiredCaps["perm"]) {
		t.Fatalf("mode groups=%v ok=%v", modeGroups, ok)
	}
	joinGroups, ok := OptionCapsFor("ipv6-join-group")
	if !ok || !reflect.DeepEqual(joinGroups, optionRequiredCaps["ipv6-join-group"]) {
		t.Fatalf("ipv6-join-group groups=%v ok=%v", joinGroups, ok)
	}
	if parse.CanonicalOptionName("ipv6-join-group") != "ipv6-join-group" {
		t.Fatalf("ipv6-join-group must not fold; got %q", parse.CanonicalOptionName("ipv6-join-group"))
	}
	if parse.CanonicalOptionName("join-group") != "ipv6-join-group" {
		t.Fatalf("join-group canonical=%q", parse.CanonicalOptionName("join-group"))
	}
	if parse.CanonicalOptionName("join-source-group") != "ipv6-join-source-group" {
		t.Fatalf("join-source-group canonical=%q", parse.CanonicalOptionName("join-source-group"))
	}
	if parse.CanonicalOptionName("mcloop6") != "ipv6-multicast-loop" || parse.CanonicalOptionName("mcloop") != "ip-multicast-loop" {
		t.Fatalf("mcloop=%q mcloop6=%q", parse.CanonicalOptionName("mcloop"), parse.CanonicalOptionName("mcloop6"))
	}
	if parse.CanonicalOptionName("mtudiscover") != "ip-mtu-discover" || parse.CanonicalOptionName("mtudiscover6") != "ipv6-mtu-discover" {
		t.Fatalf("mtudiscover=%q mtudiscover6=%q", parse.CanonicalOptionName("mtudiscover"), parse.CanonicalOptionName("mtudiscover6"))
	}
	if parse.CanonicalOptionName("add-membership") != "ip-add-membership" {
		t.Fatalf("add-membership canonical=%q", parse.CanonicalOptionName("add-membership"))
	}
	if parse.CanonicalOptionName("ext2-append") != "fs-append" || parse.CanonicalOptionName("nodump") != "fs-nodump" {
		t.Fatalf("ext2-append=%q nodump=%q", parse.CanonicalOptionName("ext2-append"), parse.CanonicalOptionName("nodump"))
	}
	if parse.CanonicalOptionName("notail") != "fs-notail" {
		t.Fatalf("notail canonical=%q", parse.CanonicalOptionName("notail"))
	}
	appendFS, ok := OptionCapsFor("fs-append")
	if !ok || !reflect.DeepEqual(appendFS, []string{"reg"}) {
		t.Fatalf("fs-append groups=%v ok=%v", appendFS, ok)
	}
	notailGroups, ok := OptionCapsFor("notail")
	if !ok || !reflect.DeepEqual(notailGroups, optionRequiredCaps["fs-notail"]) {
		t.Fatalf("notail groups=%v ok=%v", notailGroups, ok)
	}
	memberGroups, ok := OptionCapsFor("ip-add-membership")
	if !ok || reflect.DeepEqual(joinGroups, memberGroups) {
		t.Fatalf("ipv6-join-group groups=%v ip-add-membership groups=%v", joinGroups, memberGroups)
	}
	joinAliasGroups, ok := OptionCapsFor("join-group")
	if !ok || !reflect.DeepEqual(joinAliasGroups, optionRequiredCaps["join-group"]) {
		t.Fatalf("join-group groups=%v ok=%v", joinAliasGroups, ok)
	}
}
