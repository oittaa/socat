package xio

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func decodePeerPolicy(t *testing.T, text string) addrconfig.PeerPolicy {
	t.Helper()
	spec, err := parse.ParseSpec(text)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type, Group: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	return config.Network.Peer
}

func TestTCPWrapExplicitMissingTableFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.allow")
	cfg := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,hosts-allow="+missing), nil)
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err == nil {
		t.Fatal("explicit missing table unexpectedly permitted the peer")
	}
}

func TestTCPWrapOversizedExplicitTableFailsClosed(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "hosts.allow")
	if err := os.WriteFile(allow, []byte("socat: "+string(make([]byte, 70<<10))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := tcpwrapConfig{enabled: true, daemon: "socat", allow: allow, allowRequired: true}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err == nil {
		t.Fatal("unreadable explicit table unexpectedly permitted the peer")
	}
}

func TestTCPWrapMissingDefaultTablesRemainOptional(t *testing.T) {
	dir := t.TempDir()
	cfg := tcpwrapConfig{
		enabled: true,
		daemon:  "socat",
		allow:   filepath.Join(dir, "hosts.allow"),
		deny:    filepath.Join(dir, "hosts.deny"),
	}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err != nil {
		t.Fatalf("missing optional system tables should default permit: %v", err)
	}
}

func TestTCPWrapDaemonNameSelectsHostsTable(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "hosts.allow")
	deny := filepath.Join(dir, "hosts.deny")
	if err := os.WriteFile(allow, []byte("MyDaemon: 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tables := ",hosts-allow=" + allow + ",hosts-deny=" + deny

	named := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,tcpwrap=MyDaemon"+tables), nil)
	if named.daemon != "MyDaemon" {
		t.Fatalf("daemon=%q", named.daemon)
	}
	if err := tcpwrapAllowed(named, peer, nil); err != nil {
		t.Fatalf("tcpwrap=MyDaemon: %v", err)
	}

	bare := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,tcpwrap"+tables), nil)
	if bare.daemon != "socat" {
		t.Fatalf("default daemon=%q", bare.daemon)
	}
	if err := tcpwrapAllowed(bare, peer, nil); err == nil {
		t.Fatal("default daemon unexpectedly matched MyDaemon allow rule")
	}
}
