package xio

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseTCPWrap(t *testing.T) {
	s, err := parse.ParseSpec("TCP4-LISTEN:1234,hosts-allow=/tmp/ha,hosts-deny=/tmp/hd")
	if err != nil {
		t.Fatal(err)
	}
	cfg := parseTCPWrap(s, &Global{Progname: "socat"})
	if !cfg.enabled {
		t.Fatal("expected enabled")
	}
	if cfg.allow != "/tmp/ha" || cfg.deny != "/tmp/hd" {
		t.Fatalf("paths: allow=%q deny=%q", cfg.allow, cfg.deny)
	}
	if cfg.daemon != "socat" {
		t.Fatalf("daemon=%q", cfg.daemon)
	}

	s2, err := parse.ParseSpec("TCP4-LISTEN:1234,tcpwrap=test")
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := parseTCPWrap(s2, &Global{Progname: "socat"})
	if !cfg2.enabled || cfg2.daemon != "test" {
		t.Fatalf("tcpwrap=test: %+v", cfg2)
	}

	s3, err := parse.ParseSpec("TCP4-LISTEN:1234,tcpwrap-etc=/etc/foo")
	if err != nil {
		t.Fatal(err)
	}
	cfg3 := parseTCPWrap(s3, nil)
	wantAllow := filepath.Join("/etc/foo", "hosts.allow")
	wantDeny := filepath.Join("/etc/foo", "hosts.deny")
	if !cfg3.enabled || cfg3.allow != wantAllow || cfg3.deny != wantDeny {
		t.Fatalf("tcpwrap-etc: %+v", cfg3)
	}
}

func TestMatchHostsTable(t *testing.T) {
	dir := t.TempDir()
	ha := filepath.Join(dir, "hosts.allow")
	if err := os.WriteFile(ha, []byte("socat: 127.0.0.1\n# comment\nALL: 10.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !matchHostsTable(ha, "socat", "127.0.0.1", "") {
		t.Fatal("127.0.0.1 should match")
	}
	if matchHostsTable(ha, "socat", "192.0.2.1", "") {
		t.Fatal("192.0.2.1 should not match socat line")
	}
	if !matchHostsTable(ha, "other", "10.0.0.1", "") {
		t.Fatal("ALL daemon should match 10.0.0.1")
	}

	// Spaced colon form + bracketed IPv6 (TCPWRAPPERS_TCP6ADDR)
	ha6 := filepath.Join(dir, "hosts.allow6")
	if err := os.WriteFile(ha6, []byte("socat : [::1] : allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !matchHostsTable(ha6, "socat", "::1", "") {
		t.Fatal("[::1] should match client ::1")
	}
}

func TestTCPWrapAllowed(t *testing.T) {
	dir := t.TempDir()
	ha := filepath.Join(dir, "hosts.allow")
	hd := filepath.Join(dir, "hosts.deny")
	// Allow only 127.1.0.1 (SECONDADDR style); deny ALL
	if err := os.WriteFile(ha, []byte("socat: 127.1.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hd, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := tcpwrapConfig{
		enabled: true,
		daemon:  "socat",
		allow:   ha,
		deny:    hd,
	}
	// 127.0.0.1 must be refused
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err == nil {
		t.Fatal("expected refuse for 127.0.0.1")
	}
	// 127.1.0.1 allowed
	peer2 := &net.TCPAddr{IP: net.ParseIP("127.1.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer2, nil); err != nil {
		t.Fatalf("expected allow for 127.1.0.1: %v", err)
	}
}

func TestPeerAllowedG_TCPWrap(t *testing.T) {
	dir := t.TempDir()
	ha := filepath.Join(dir, "hosts.allow")
	hd := filepath.Join(dir, "hosts.deny")
	if err := os.WriteFile(ha, []byte("test : ALL : allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hd, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// MULTIOPTS: hosts-allow + tcpwrap=test
	s, err := parse.ParseSpec("TCP4-LISTEN:1234,hosts-allow=" + ha + ",tcpwrap=test")
	if err != nil {
		t.Fatal(err)
	}
	// Without deny path, default /etc/hosts.deny may not deny; set deny via hosts-deny
	s2, err := parse.ParseSpec("TCP4-LISTEN:1234,hosts-allow=" + ha + ",hosts-deny=" + hd + ",tcpwrap=test")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err == nil {
			defer func() { _ = c.Close() }()
			// hold open briefly
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := PeerAllowedG(s2, conn, &Global{Progname: "socat"}); err != nil {
		t.Fatalf("daemon test should allow ALL: %v", err)
	}
	// Wrong daemon name should fall through to deny ALL
	s3, err := parse.ParseSpec("TCP4-LISTEN:1234,hosts-allow=" + ha + ",hosts-deny=" + hd + ",tcpwrap=wrong")
	if err != nil {
		t.Fatal(err)
	}
	if err := PeerAllowedG(s3, conn, nil); err == nil {
		t.Fatal("expected refuse for wrong daemon")
	}
	_ = s
}
