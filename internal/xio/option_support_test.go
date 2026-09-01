package xio

import (
	"testing"
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

	if !OptionSupportedOnAddress(tcp, nil, nil, []string{CapOpen, CapFD}) {
		t.Fatal("append (open|fd) must be allowed on TCP")
	}
	if OptionSupportedOnAddress(tcp, nil, nil, []string{CapFork}) {
		t.Fatal("pty (fork) must be rejected on TCP")
	}
	if OptionSupportedOnAddress(tcp, nil, nil, []string{CapTermios}) {
		t.Fatal("echo (termios) must be rejected on TCP")
	}
	if !OptionSupportedOnAddress(tcp, nil, nil, nil) {
		t.Fatal("unrestricted options must be allowed on TCP")
	}
	if OptionSupportedOnAddress(open, nil, nil, []string{CapIPUDP, CapIPTCP, CapIPSCTP}) {
		t.Fatal("lowport must be rejected on OPEN")
	}

	tlsTypes := []string{"TLS", "PROXY", "WSS", "QUIC"}
	tlsGroups := []string{GroupTLS, GroupWebSocket, GroupQUIC, GroupProxy}
	if !OptionSupportedOnAddress(proxy, tlsGroups, tlsTypes, []string{CapOpenSSL}) {
		t.Fatal("Go extra: verify on PROXY")
	}
	if OptionSupportedOnAddress(tcp, tlsGroups, tlsTypes, []string{CapOpenSSL}) {
		t.Fatal("verify must stay rejected on TCP")
	}
	wsReg := AddressRegistration{Name: "WS", Group: GroupWebSocket, OptionCaps: CapsTCPConnect}
	if OptionSupportedOnAddress(wsReg, tlsGroups, tlsTypes, []string{CapOpenSSL}) {
		t.Fatal("cert must stay rejected on plain WS even though WSS shares the help section")
	}

	wsGroups := []string{GroupWebSocket}
	if !OptionSupportedOnAddress(ws, wsGroups, nil, []string{CapExec}) {
		t.Fatal("Go extra: path on WS")
	}
	if OptionSupportedOnAddress(tcp, wsGroups, nil, []string{CapExec}) {
		t.Fatal("path must be rejected on TCP")
	}

	handshakeTypes := []string{
		"TLS", "TLS-CONNECT", "TLS-LISTEN", "OPENSSL", "WS", "WSS", "QUIC", "PROXY", "SOCKS5",
	}
	if !OptionSupportedOnAddress(proxy, nil, handshakeTypes, nil) {
		t.Fatal("Go extra: handshake-timeout on PROXY")
	}
	if !OptionSupportedOnAddress(ws, nil, handshakeTypes, nil) {
		t.Fatal("Go extra: handshake-timeout on WS")
	}
	if OptionSupportedOnAddress(tcp, nil, handshakeTypes, nil) {
		t.Fatal("handshake-timeout must stay rejected on TCP")
	}
	if OptionSupportedOnAddress(open, nil, handshakeTypes, nil) {
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
	for _, name := range []string{"dsusp", "vdsusp", "b900", "b3600", "ccid", "udplite-send-cscov", "ptmx", "openpty", "pty-wait-slave"} {
		if have[name] {
			t.Errorf("TermiosOptionNames must not include %q", name)
		}
	}
	if len(names) < 50 {
		t.Fatalf("TermiosOptionNames returned %d names, want a full termios set", len(names))
	}
}

func TestTermiosHelpNamesAreRecognized(t *testing.T) {
	pty := map[string]bool{
		"ptmx": true, "openpty": true,
		"pty-wait-slave": true, "wait-slave": true, "waitslave": true,
		"pty-interval": true, "pty-intervall": true,
	}
	have := make(map[string]bool)
	for _, name := range TermiosOptionNames() {
		have[name] = true
	}
	for _, name := range TermiosHelpNames() {
		if pty[name] {
			if have[name] {
				t.Errorf("PTY name %q must not be in TermiosOptionNames", name)
			}
			continue
		}
		if !have[name] {
			t.Errorf("advertised termios name %q missing from TermiosOptionNames", name)
		}
	}
}
