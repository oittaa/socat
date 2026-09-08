package dtls13

import (
	"bytes"
	"testing"
	"time"
)

func driveLimitedSessions(t *testing.T, clientConfig, serverConfig *Config, clientLimit, serverLimit int, dropUntil int) (*session, *session, map[string]struct{}) {
	t.Helper()
	var packets []testDatagram
	seen := make(map[string]struct{})
	var client, server *session
	sender := func(fromClient bool, limit int) func([]byte) error {
		return func(data []byte) error {
			if dropUntil > 0 && fromClient && (client == nil || client.working.reductions < dropUntil) {
				return nil
			}
			if limit > 0 && len(data) > limit {
				return messageTooLongError()
			}
			key := string(data)
			if _, ok := seen[key]; ok {
				t.Fatal("retransmitted an identical datagram")
			}
			seen[key] = struct{}{}
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	now := time.Unix(100, 0)
	var err error
	server, err = newTestServerSession(serverConfig, sender(false, serverLimit))
	if err != nil {
		t.Fatal(err)
	}
	client, err = newClientSession(clientConfig, sender(true, clientLimit), now)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 4000; step++ {
		if len(packets) != 0 {
			p := packets[0]
			packets = packets[1:]
			destination := client
			if p.fromClient {
				destination = server
			}
			if _, err := destination.receive(p.data, now); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.outbound.complete {
			return client, server, seen
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled")
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake did not finish")
	return nil, nil, nil
}

func TestHandshakeRecoversFromEMSGSIZE(t *testing.T) {
	limitedCfg, peerCfg := handshakeConfigs(t)
	limitedCfg.MTU, peerCfg.MTU = 4000, 4000
	limited, peer, _ := driveLimitedSessions(t, limitedCfg, peerCfg, 600, 0, 0)
	if limited.working.reductions == 0 || limited.effectiveMTU() >= 4000 || limited.effectiveMTU() < minPathMTU {
		t.Fatalf("limited MTU %d after %d reductions", limited.effectiveMTU(), limited.working.reductions)
	}
	if peer.working.reductions != 0 || peer.effectiveMTU() != 4000 {
		t.Fatalf("unlimited peer shrank: mtu=%d reductions=%d", peer.effectiveMTU(), peer.working.reductions)
	}
	if err := limited.application([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeEMSGSIZEIsolatedFromSecondAssociation(t *testing.T) {
	aClient, aServer := handshakeConfigs(t)
	bClient, bServer := handshakeConfigs(t)
	aClient.MTU, aServer.MTU, bClient.MTU, bServer.MTU = 4000, 4000, 4000, 4000
	limited, _, _ := driveLimitedSessions(t, aClient, aServer, 600, 0, 0)
	plain, _, _ := driveLimitedSessions(t, bClient, bServer, 0, 0, 0)
	if limited.working.reductions == 0 {
		t.Fatal("injected EMSGSIZE did not shrink")
	}
	if plain.working.reductions != 0 || plain.effectiveMTU() != 4000 {
		t.Fatalf("second association shrank: mtu=%d reductions=%d", plain.effectiveMTU(), plain.working.reductions)
	}
}

func TestHandshakeShrinksOnUnansweredFlight(t *testing.T) {
	clientCfg, serverCfg := handshakeConfigs(t)
	clientCfg.MTU, serverCfg.MTU = 2000, 2000
	client, server, _ := driveLimitedSessions(t, clientCfg, serverCfg, 0, 0, 2)
	if client.working.reductions < 2 || client.working.reductions > maxMTUReductions {
		t.Fatalf("unanswered reductions = %d", client.working.reductions)
	}
	if client.effectiveMTU() >= 2000 || client.effectiveMTU() < minPathMTU {
		t.Fatalf("unanswered MTU %d", client.effectiveMTU())
	}
	if server.effectiveMTU() != 2000 {
		t.Fatalf("server shrank without sending: %d", server.effectiveMTU())
	}
}

func TestApplicationWriteDoesNotRetransmitEMSGSIZE(t *testing.T) {
	clientCfg, serverCfg := handshakeConfigs(t)
	client, _, packets := driveSessions(t, clientCfg, serverCfg, false, false)
	before := client.effectiveMTU()
	client.send = func([]byte) error { return messageTooLongError() }
	if err := client.application([]byte("app")); !isMessageTooLong(err) {
		t.Fatalf("application EMSGSIZE: %v", err)
	}
	if client.effectiveMTU() >= before {
		t.Fatal("application EMSGSIZE did not reduce the advertised budget")
	}
	if err := client.application([]byte("still")); !isMessageTooLong(err) {
		t.Fatalf("second application write: %v", err)
	}
	if len(*packets) != 0 {
		t.Fatal("application datagram was retransmitted")
	}
}
