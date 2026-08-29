package testutil

import (
	"net"
	"testing"
)

func TestListenTCPAndUDP(t *testing.T) {
	tcp, udp, addr, err := ListenTCPAndUDP("127.0.0.1", "4")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	defer func() { _ = udp.Close() }()

	_, tcpPort, err := net.SplitHostPort(tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, udpPort, err := net.SplitHostPort(udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tcpPort != udpPort || addr != net.JoinHostPort("127.0.0.1", tcpPort) {
		t.Fatalf("tcp=%s udp=%s addr=%s", tcp.Addr(), udp.LocalAddr(), addr)
	}
}

func TestDynamicPortVisitsEveryCandidateOnce(t *testing.T) {
	seen := make(map[int]struct{}, dynamicPortCount)
	for attempt := 0; attempt < dynamicPortCount; attempt++ {
		port := dynamicPort(1234, attempt)
		if port < dynamicPortFirst || port >= dynamicPortFirst+dynamicPortCount {
			t.Fatalf("candidate %d is outside the dynamic range", port)
		}
		if _, duplicate := seen[port]; duplicate {
			t.Fatalf("candidate %d repeated at attempt %d", port, attempt)
		}
		seen[port] = struct{}{}
	}
}
