package dtls13

import (
	"context"
	"testing"
	"time"
)

func TestUnfragmentedProbesOffByDefault(t *testing.T) {
	client, server, _ := connectionPair(t)
	if client.transport.unfragmented || client.session.canProbe {
		t.Fatal("default client enabled DF probes")
	}
	if server.transport.unfragmented || server.session.canProbe {
		t.Fatal("default listener association enabled DF probes")
	}
}

func TestUnfragmentedProbesNotInheritedByListener(t *testing.T) {
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
	if !client.transport.direct {
		t.Fatal("client socket is not dedicated")
	}
	if client.session.canProbe != client.transport.unfragmented {
		t.Fatal("canProbe desynced from dedicated-socket DF setup")
	}
	server := peer.(*Conn)
	if server.transport.unfragmented || server.session.canProbe || server.transport.direct {
		t.Fatal("listener association inherited unfragmented probes")
	}
}
