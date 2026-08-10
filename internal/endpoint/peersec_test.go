package endpoint

import (
	"net"
	"testing"
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
