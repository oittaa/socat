package xio

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestCompileIPRangeWrapsLookupError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, spec := range []string{"blocked.test", "blocked.test:255.255.255.255"} {
		_, err := compileIPRange(ctx, spec, net.DefaultResolver)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("compileIPRange(%q) err=%v want context.Canceled", spec, err)
		}
	}
}

func TestIPInRangeHostnameMask(t *testing.T) {
	// Classic FDLEAK: range=localhost:255.255.255.255
	ok, err := ipInRange(net.ParseIP("127.0.0.1"), "localhost:255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("127.0.0.1 should match range=localhost:255.255.255.255")
	}
	ok, err = ipInRange(net.ParseIP("127.1.0.1"), "localhost:255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("127.1.0.1 should not match range=localhost:255.255.255.255")
	}
}

func TestPeerFilterNoOptionsDoesNotAllocate(t *testing.T) {
	filter, err := NewPeerFilter(context.Background(), addrconfig.PeerPolicy{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	if got := testing.AllocsPerRun(1000, func() {
		if err := filter.AllowAddr(peer, nil); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("AllowAddr allocations = %v, want 0", got)
	}
}

func TestPeerFilterRangeAcceptsIPAddr(t *testing.T) {
	spec, err := parse.ParseSpec("IP4-DATAGRAM:127.0.0.1:254,range=127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "IP4-DATAGRAM", Group: "Raw IP"})
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewPeerFilter(context.Background(), config.Network.Peer, LookupResolver(config), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := filter.AllowAddr(&net.IPAddr{IP: net.IPv4(127, 1, 0, 1)}, nil); err != nil {
		t.Fatalf("127.1.0.1 in 127.0.0.0/8: %v", err)
	}
	if err := filter.AllowAddr(&net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}, nil); err == nil {
		t.Fatal("10.0.0.1 must be refused by range=127.0.0.0/8")
	}
}

func TestCloseRefusedPeerNil(t *testing.T) {
	CloseRefusedPeer(nil)
}
