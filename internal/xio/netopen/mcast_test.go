package netopen

import (
	"testing"
)

func TestParseMcastSpecBracketIPv6(t *testing.T) {
	g, iface, err := parseMcastSpec("[ff02::2]:eth0")
	if err != nil {
		t.Fatal(err)
	}
	if g.String() != "ff02::2" || iface != "eth0" {
		t.Fatalf("group=%s iface=%q", g, iface)
	}
}

func TestParseMcastSpecIPv4(t *testing.T) {
	g, iface, err := parseMcastSpec("224.1.2.3:127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if g.String() != "224.1.2.3" || iface != "127.0.0.1" {
		t.Fatalf("group=%s iface=%q", g, iface)
	}
}
