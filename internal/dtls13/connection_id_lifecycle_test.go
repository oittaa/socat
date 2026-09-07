package dtls13

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestCIDRequestCountsAndExhaustion(t *testing.T) {
	for _, requesterClient := range []bool{true, false} {
		for _, count := range []byte{0, 1, maxConnectionIDs, 255} {
			t.Run(fmt.Sprintf("client=%t/count=%d", requesterClient, count), func(t *testing.T) {
				a, b := handshakeConfigs(t)
				a.ConnectionIDLength, b.ConnectionIDLength = 1, 32
				a.MTU, b.MTU = 256, 256
				client, server, packets := driveSessions(t, a, b, false, false)
				requester, issuer := client, server
				if !requesterClient {
					requester, issuer = server, client
				}
				now := time.Unix(1000, 0)
				if err := requester.requestCIDs(count, now); err != nil {
					t.Fatal(err)
				}
				// Verify the production request encoding independently of its parser.
				r, _, err := parseRecord((*packets)[0].data, len(issuer.handshake.localCID))
				if err != nil {
					t.Fatal(err)
				}
				window := issuer.read[3].window
				_, typ, wire, err := issuer.read[3].keys.decodeRecord(r, 3, issuer.handshake.localCID, &window)
				seq := uint16(requester.handshake.sequence - 1)
				if err != nil || typ != contentHandshake || !bytes.Equal(wire, cidWireFragment(msgRequestConnectionID, seq, 1, 0, []byte{count})) {
					t.Fatalf("request encoding: %x, %v", wire, err)
				}
				deliverSessionPackets(t, client, server, packets, now)
				want := min(int(count), maxConnectionIDs-1)
				if requester.cidRequested || len(requester.peerSpareCIDs) != want || len(issuer.localCIDs) != want+1 {
					t.Fatalf("bounded response: pending=%t, spares=%d, issued=%d", requester.cidRequested, len(requester.peerSpareCIDs), len(issuer.localCIDs))
				}
				order := slices.Clone(requester.peerSpareCIDs)
				for _, id := range order {
					requester.useSpareCID()
					if !bytes.Equal(requester.handshake.peerCID, id) {
						t.Fatal("spares were not consumed in issuance order")
					}
					if err := requester.application(id); err != nil {
						t.Fatal(err)
					}
					data := deliverSessionPackets(t, client, server, packets, now)
					if len(data) != 1 || !bytes.Equal(data[0], id) {
						t.Fatal("spare did not route application data")
					}
				}
				if count == 0 {
					return
				}
				// A full issuer pool rotates immediately, then fulfills the
				// pending request with new spares after retiring the old pool.
				for range maxConnectionIDs + 2 {
					for len(requester.peerSpareCIDs) != 0 {
						requester.useSpareCID()
					}
					if err := requester.advancePost(now); err != nil {
						t.Fatal(err)
					}
					deliverSessionPackets(t, client, server, packets, now)
					requireCIDRenewalComplete(t, requester, issuer)
				}
			})
		}
	}
}

func requireCIDRenewalComplete(t *testing.T, requester, issuer *session) {
	t.Helper()
	if len(requester.peerSpareCIDs) == 0 || requester.cidRequested || issuer.cidResponse != nil || len(issuer.immediateCIDs) != 0 ||
		requester.post[msgRequestConnectionID] != nil || issuer.post[msgNewConnectionID] != nil {
		t.Fatalf("CID renewal incomplete: spares=%d, request=%t, response=%v, immediate=%d, request flight=%t, response flight=%t",
			len(requester.peerSpareCIDs), requester.cidRequested, issuer.cidResponse, len(issuer.immediateCIDs),
			requester.post[msgRequestConnectionID] != nil, issuer.post[msgNewConnectionID] != nil)
	}
	if len(requester.peerSpareCIDs) > maxConnectionIDs || len(issuer.localCIDs) > maxConnectionIDs {
		t.Fatalf("CID pool bound exceeded: spares=%d, issued=%d", len(requester.peerSpareCIDs), len(issuer.localCIDs))
	}
}

func TestCIDNegotiatedDirections(t *testing.T) {
	for _, clientEmpty := range []bool{true, false} {
		for _, negotiated := range []bool{true, false} {
			for _, typ := range []byte{msgNewConnectionID, msgRequestConnectionID} {
				t.Run(fmt.Sprintf("clientEmpty=%t/negotiated=%t/type=%d", clientEmpty, negotiated, typ), func(t *testing.T) {
					a, b := handshakeConfigs(t)
					client, server, packets := driveSessions(t, a, b, false, false)
					empty, other := client, server
					if !clientEmpty {
						empty, other = server, client
					}
					// Model RFC 9146 section 3's asymmetric handshake result. Our
					// public configuration issues only nonempty CIDs or no extension.
					empty.handshake.localCID, other.handshake.peerCID = nil, nil
					for _, s := range []*session{client, server} {
						s.handshake.cidNegotiated = negotiated
						if err := s.handshake.finish(); err != nil {
							t.Fatal(err)
						}
					}
					now := time.Unix(1000, 0)
					if err := empty.provideCIDs(1, false, now); !errors.Is(err, errUnexpectedMessage) {
						t.Fatalf("empty receiving CID allowed issuance: %v", err)
					}
					if err := other.requestCIDs(1, now); !errors.Is(err, errUnexpectedMessage) {
						t.Fatalf("empty sending CID allowed request: %v", err)
					}
					if negotiated {
						if err := empty.requestCIDs(1, now); err != nil {
							t.Fatal(err)
						}
						deliverSessionPackets(t, client, server, packets, now)
						if len(empty.peerSpareCIDs) != 1 {
							t.Fatal("valid direction of asymmetric CID exchange failed")
						}
					}
					sender, receiver, body := empty, other, []byte{0, 0, 1}
					if typ == msgRequestConnectionID {
						sender, receiver, body = other, empty, []byte{1}
					}
					sendCIDWire(t, sender, typ, body)
					if _, err := receiver.receive((*packets)[0].data, now); !errors.Is(err, errUnexpectedMessage) {
						t.Fatalf("forbidden authenticated CID message: %v", err)
					}
				})
			}
		}
	}
}

func TestCIDOverlappingRequestsAndIssuance(t *testing.T) {
	for _, requesterClient := range []bool{true, false} {
		t.Run(fmt.Sprintf("client=%t", requesterClient), func(t *testing.T) {
			a, b := handshakeConfigs(t)
			client, server, packets := driveSessions(t, a, b, false, false)
			requester, issuer := client, server
			if !requesterClient {
				requester, issuer = server, client
			}
			now := time.Unix(1000, 0)
			if err := issuer.provideCIDs(1, true, now); err != nil {
				t.Fatal(err)
			}
			if err := issuer.provideCIDs(1, false, now); !errors.Is(err, errUpdatePending) {
				t.Fatalf("overlapping NewConnectionId allowed: %v", err)
			}
			*packets = nil // Hold the immediate update so requests remain queued.
			if err := requester.requestCIDs(1, now); err != nil {
				t.Fatal(err)
			}
			if err := requester.requestCIDs(1, now); !errors.Is(err, errUpdatePending) {
				t.Fatalf("overlapping local request allowed: %v", err)
			}
			request := (*packets)[0].data
			*packets = nil
			if _, err := issuer.receive(request, now); err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.receive(request, now); err != nil {
				t.Fatalf("record replay treated as a new request: %v", err)
			}
			if err := requester.transmit(requester.post[msgRequestConnectionID], now); err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.receive((*packets)[len(*packets)-1].data, now); err != nil {
				t.Fatalf("fresh-record retransmission treated as a new request: %v", err)
			}
			*packets = nil
			sendCIDWire(t, requester, msgRequestConnectionID, []byte{1})
			if _, err := issuer.receive((*packets)[0].data, now); !errors.Is(err, alertError(52)) {
				t.Fatalf("new overlapping request: %v, want too_many_cids_requested", err)
			}
			if issuer.cidResponse == nil || *issuer.cidResponse != 1 || len(issuer.localCIDs) != 2 || len(issuer.post) != 1 {
				t.Fatal("overlapping request grew pending state")
			}
		})
	}
}

func TestCIDSustainedPoolRenewal(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	requester, issuer := client, server
	if err := requester.requestCIDs(255, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	seen := map[string]int{}
	for round := range maxConnectionIDs + 3 {
		for len(requester.peerSpareCIDs) != 0 {
			requester.useSpareCID()
		}
		id := string(requester.handshake.peerCID)
		seen[id]++
		if err := requester.application([]byte{byte(round)}); err != nil {
			t.Fatal(err)
		}
		if data := deliverSessionPackets(t, client, server, packets, now); len(data) != 1 {
			t.Fatalf("round %d: application after spare consume", round)
		}
		if err := requester.advancePost(now); err != nil {
			t.Fatal(err)
		}
		deliverSessionPackets(t, client, server, packets, now)
		requireCIDRenewalComplete(t, requester, issuer)
	}
	if len(seen) < 2 {
		t.Fatal("sustained consume did not rotate the sending CID")
	}
}

func TestCIDRenewalLostImmediateACK(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestCIDs(255, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	for len(client.peerSpareCIDs) != 0 {
		client.useSpareCID()
	}
	if err := client.advancePost(now); err != nil {
		t.Fatal(err)
	}
	var request []byte
	rest := (*packets)[:0]
	for _, p := range *packets {
		if p.fromClient {
			request = p.data
		} else {
			rest = append(rest, p)
		}
	}
	*packets = rest
	if request == nil {
		t.Fatal("missing CID request")
	}
	if _, err := server.receive(request, now); err != nil {
		t.Fatal(err)
	}
	var immediate [][]byte
	held := (*packets)[:0]
	for _, p := range *packets {
		if p.fromClient {
			held = append(held, p)
		} else {
			immediate = append(immediate, p.data)
		}
	}
	*packets = held
	if len(immediate) == 0 {
		t.Fatal("issuer did not send immediate rotation")
	}
	for _, datagram := range immediate {
		if _, err := client.receive(datagram, now); err != nil {
			t.Fatal(err)
		}
	}
	*packets = nil
	now = server.deadline()
	if now.IsZero() {
		t.Fatal("issuer dropped retransmission of unacknowledged rotation")
	}
	if err := server.tick(now); err != nil {
		t.Fatal(err)
	}
	if len(*packets) == 0 {
		t.Fatal("lost ACK did not retransmit NewConnectionId")
	}
	deliverSessionPackets(t, client, server, packets, now)
	// A duplicate handshake message is acknowledged by the delayed ACK timer.
	now = client.deadline()
	if now.IsZero() {
		t.Fatal("retransmitted rotation did not schedule an ACK")
	}
	if err := client.tick(now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	requireCIDRenewalComplete(t, client, server)
}

func TestCIDRenewalWaitsForKeyUpdate(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := server.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	if err := client.requestCIDs(1, now); err != nil {
		t.Fatal(err)
	}
	var request []byte
	rest := (*packets)[:0]
	for _, p := range *packets {
		if p.fromClient {
			request = p.data
		} else {
			rest = append(rest, p)
		}
	}
	*packets = rest
	if request == nil {
		t.Fatal("missing CID request")
	}
	if _, err := server.receive(request, now); err != nil {
		t.Fatal(err)
	}
	if server.post[msgNewConnectionID] != nil || server.cidResponse == nil {
		t.Fatal("CID issuance started before KeyUpdate was acknowledged")
	}
	deliverSessionPackets(t, client, server, packets, now)
	requireCIDRenewalComplete(t, client, server)
}

func TestCIDImmediateUpdatesPendingPathProbe(t *testing.T) {
	p := newTestPaths(t)
	now := time.Unix(2000, 0)
	for len(p.client.peerSpareCIDs) != 0 {
		p.client.useSpareCID()
	}
	moved := netip.MustParseAddrPort("192.0.2.1:1001")
	if err := p.client.application([]byte("move")); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) == 0 {
		t.Fatal("missing application datagram")
	}
	app := p.packets[len(p.packets)-1]
	p.packets = p.packets[:len(p.packets)-1]
	if _, err := p.server.receiveFrom(app.data, packetPath{moved, 1}, now); err != nil {
		t.Fatal(err)
	}
	if p.server.path == nil || p.server.path.probe == nil {
		t.Fatal("address change did not start path validation")
	}
	if err := p.client.advancePost(now); err != nil {
		t.Fatal(err)
	}
	if p.server.path.probe == nil {
		t.Fatal("CID request during validation dropped the path probe")
	}
}
