//go:build linux

package dtls13

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ipv4MTUDiscoverMode(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mode int
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		mode, ctrlErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	}); err != nil {
		t.Fatal(err)
	}
	if ctrlErr != nil {
		t.Fatal(ctrlErr)
	}
	return mode
}

func TestUnfragmentedProbesUsesPMTUDISCProbe(t *testing.T) {
	conn := testUDP(t)
	ok, err := enableUnfragmentedSends(conn)
	if err != nil || !ok {
		t.Fatalf("enable: ok=%v err=%v", ok, err)
	}
	mode := ipv4MTUDiscoverMode(t, conn)
	if mode != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("IP_MTU_DISCOVER=%d want PMTUDISC_PROBE=%d (not DO=%d)", mode, unix.IP_PMTUDISC_PROBE, unix.IP_PMTUDISC_DO)
	}
}

func TestSharedListenerDoesNotEnableUnfragmentedProbes(t *testing.T) {
	listenConn := testUDP(t)
	clientConn := testUDP(t)
	clientCfg, serverCfg := handshakeConfigs(t)
	serverCfg.UnfragmentedProbes = true
	clientCfg.UnfragmentedProbes = true
	listener, err := Listen(listenConn, serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if listener.transport.unfragmented || listener.transport.direct {
		t.Fatal("shared listener advertised unfragmented probes")
	}
	before := ipv4MTUDiscoverMode(t, listenConn)
	if before == unix.IP_PMTUDISC_PROBE {
		t.Fatal("Listen set PMTUDISC_PROBE on the shared socket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Client(ctx, clientConn, listener.Addr(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if !client.transport.unfragmented || !client.session.canProbe {
		t.Fatal("dedicated client socket did not enable probes")
	}
	if ipv4MTUDiscoverMode(t, clientConn) != unix.IP_PMTUDISC_PROBE {
		t.Fatal("client socket is not PMTUDISC_PROBE")
	}
	if ipv4MTUDiscoverMode(t, listenConn) != before {
		t.Fatal("client setup changed the shared listener fragmentation policy")
	}
	server := peer.(*Conn)
	if server.transport.unfragmented || server.session.canProbe {
		t.Fatal("listener association inherited unfragmented probes")
	}
}

func TestUnfragmentedProbesDefaultOff(t *testing.T) {
	client, _, _ := connectionPair(t)
	if client.transport.unfragmented || client.session.canProbe {
		t.Fatal("default client enabled DF probes")
	}
	if ipv4MTUDiscoverMode(t, client.transport.udp) == unix.IP_PMTUDISC_PROBE {
		t.Fatal("default client socket is PMTUDISC_PROBE")
	}
}
