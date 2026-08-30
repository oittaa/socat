package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

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
	filter := NewPeerFilter(parse.Spec{}, nil)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	if got := testing.AllocsPerRun(1000, func() {
		if err := filter.AllowAddr(peer, nil); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("AllowAddr allocations = %v, want 0", got)
	}
}

func TestCompiledIPRangeForms(t *testing.T) {
	tests := []struct {
		name string
		peer string
		spec string
		want bool
	}{
		{"cidr-match", "127.1.2.3", "127.0.0.0/8", true},
		{"cidr-miss", "192.0.2.1", "127.0.0.0/8", false},
		{"ipv6-cidr", "2001:db8::9", "[2001:db8::]/32", true},
		{"address-mask", "127.9.8.7", "127.0.0.0:255.0.0.0", true},
		{"exact", "192.0.2.1", "192.0.2.1", true},
		{"hex-sockaddr", "127.8.9.10", "x0000x7f000000:x0000xff000000", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := compileIPRange(tc.spec, net.DefaultResolver)
			if err != nil {
				t.Fatal(err)
			}
			if got := matcher(net.ParseIP(tc.peer)); got != tc.want {
				t.Fatalf("match(%s, %q) = %v, want %v", tc.peer, tc.spec, got, tc.want)
			}
		})
	}
}
