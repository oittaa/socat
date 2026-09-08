package xio

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestTCPWrapExplicitMissingTableFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.allow")
	s, err := parse.ParseSpec("TCP4-LISTEN:1234,hosts-allow=" + missing)
	if err != nil {
		t.Fatal(err)
	}
	cfg := parseTCPWrap(s, nil)
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
