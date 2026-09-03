//go:build linux || darwin

package testutil

import (
	"net"
	"testing"
)

// IPv4LoopbackInterface returns the interface that owns 127.0.0.1.
func IPv4LoopbackInterface(t testing.TB) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	want := net.IPv4(127, 0, 0, 1)
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.Equal(want) {
				return ifi.Name
			}
		}
	}
	t.Fatal("no interface has 127.0.0.1")
	return ""
}
