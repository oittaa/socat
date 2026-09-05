package dtls13

import (
	"bytes"
	"errors"
	"fmt"
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
				// Low-water requests may fill remaining capacity, but cannot renew an
				// issuer's full pool. Explicit immediate rotation releases that pool.
				for range maxConnectionIDs {
					for len(requester.peerSpareCIDs) != 0 {
						requester.useSpareCID()
					}
					if err := requester.advancePost(now); err != nil {
						t.Fatal(err)
					}
					deliverSessionPackets(t, client, server, packets, now)
				}
				last := bytes.Clone(requester.handshake.peerCID)
				requester.useSpareCID()
				if !bytes.Equal(last, requester.handshake.peerCID) {
					t.Fatal("exhausted pool changed the sending CID")
				}
				if err := issuer.provideCIDs(1, true, now); err != nil {
					t.Fatal(err)
				}
				deliverSessionPackets(t, client, server, packets, now)
				if err := requester.requestCIDs(1, now); err != nil {
					t.Fatal(err)
				}
				deliverSessionPackets(t, client, server, packets, now)
				if len(issuer.localCIDs) != 2 || len(requester.peerSpareCIDs) != 1 {
					t.Fatal("explicit rotation did not restore spare issuance capacity")
				}
			})
		}
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
