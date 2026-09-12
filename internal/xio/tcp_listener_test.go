package xio

import (
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func decodeListen(t *testing.T, raw string) addrconfig.Address {
	t.Helper()
	spec, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{
		Type:   spec.Type,
		Role:   addrconfig.AddressRoleListen,
		Family: addrconfig.IPFamilyIPv4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestTCPListenAddressRejectsBindColonPort(t *testing.T) {
	ctx := t.Context()
	for _, raw := range []string{
		"TCP4-LISTEN:0,bind=:0",
		"TCP4-LISTEN:0,bind=:8080",
		"TCP4-LISTEN:0,bind=127.0.0.1:12345",
	} {
		config := decodeListen(t, raw)
		addr, err := TCPListenAddress(ctx, config, "tcp4", config.Network.ListenPort)
		if err == nil {
			t.Fatalf("%s: TCPListenAddress=%q want reject", raw, addr)
		}
		if strings.HasPrefix(addr, ":") {
			t.Fatalf("%s: empty-host listen address %q", raw, addr)
		}
	}
}

func TestTCPListenAddressBindHostKeepsPositionalPort(t *testing.T) {
	ctx := t.Context()
	config := decodeListen(t, "TCP4-LISTEN:0,bind=127.0.0.1")
	addr, err := TCPListenAddress(ctx, config, "tcp4", config.Network.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("host=%q want 127.0.0.1", host)
	}
	if port != "0" {
		t.Fatalf("port=%q want positional 0", port)
	}

	ln, err := ListenTCP(ctx, config, "tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := ln.Addr().(*net.TCPAddr)
	if !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("bound %v", got)
	}
}

func TestTCPListenWithoutBindAIPassiveZeroUsesLoopback(t *testing.T) {
	ctx := t.Context()
	config := decodeListen(t, "TCP4-LISTEN:0,ai-passive=0")
	addr, err := TCPListenAddress(ctx, config, "tcp4", config.Network.ListenPort)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("host=%q want loopback", host)
	}
}
