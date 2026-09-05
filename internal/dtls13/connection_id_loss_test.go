package dtls13

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestCIDLossReorderAndConcurrentKeyUpdate(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		for _, fault := range []string{"none", "request", "response", "ack", "all"} {
			if immediate && fault == "request" {
				continue // Immediate issuance does not need a request.
			}
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("immediate=%t/drop=%s/reverse=%t", immediate, fault, reverse), func(t *testing.T) {
					a, b := handshakeConfigs(t)
					a.ConnectionIDLength, b.ConnectionIDLength = 32, 32
					a.MTU, b.MTU = 256, 256
					client, server, _ := driveSessions(t, a, b, false, false)
					now := time.Unix(1000, 0)
					var packets []testDatagram
					dropped, duplicated := make(map[string]bool), make(map[string]bool)
					preceding := make(map[bool][]*flight)
					for _, s := range []*session{client, server} {
						s.send = func(data []byte) error {
							// Inspect with the sending key at emission time, before an
							// epoch can be retired. Delivery still uses the real receiver.
							epoch := s.currentWriteEpoch()
							r, _, err := parseRecord(data, len(s.handshake.peerCID))
							if err != nil {
								t.Fatal(err)
							}
							var window replayWindow
							_, typ, body, err := s.write[epoch].keys.decodeRecord(r, epoch, s.handshake.peerCID, &window)
							if err != nil {
								t.Fatal(err)
							}
							if epoch > 3 {
								for _, f := range preceding[s.handshake.client] {
									if !f.complete {
										t.Fatal("new-epoch record overtook an unacknowledged CID/KeyUpdate flight")
									}
								}
							}
							kind := "other"
							if typ == contentACK {
								kind = "ack"
							} else if typ == contentHandshake && len(body) != 0 {
								switch body[0] {
								case msgRequestConnectionID:
									kind = "request"
								case msgNewConnectionID:
									kind = "response"
								}
							}
							key := fmt.Sprintf("%t/%s", s.handshake.client, kind)
							if (fault == kind || fault == "all" && kind != "other") && !dropped[key] {
								dropped[key] = true
								return nil
							}
							packet := testDatagram{s.handshake.client, bytes.Clone(data)}
							packets = append(packets, packet)
							if kind != "other" && !duplicated[key] {
								duplicated[key] = true
								packets = append(packets, packet)
							}
							return nil
						}
					}
					for _, s := range []*session{client, server} {
						var err error
						if immediate {
							err = s.provideCIDs(1, true, now)
						} else {
							err = s.requestCIDs(255, now)
						}
						if err != nil {
							t.Fatal(err)
						}
						if err := s.requestKeyUpdate(false, now); err != nil {
							t.Fatal(err)
						}
						for _, f := range s.post {
							preceding[s.handshake.client] = append(preceding[s.handshake.client], f)
						}
					}
					for step := 0; ; step++ {
						if step == 2000 {
							t.Fatal("CID recovery exceeded deterministic event bound")
						}
						for _, s := range []*session{client, server} {
							if len(s.post) > 3 || len(s.localCIDs) > maxConnectionIDs+1 || len(s.peerSpareCIDs) > maxConnectionIDs || len(s.reassembly.pending) > maxPendingMessages || s.reassembly.buffered > 2*maxHandshakeBody {
								t.Fatal("CID recovery exceeded resource bounds")
							}
						}
						if len(packets) != 0 {
							index := 0
							if reverse {
								index = len(packets) - 1
							}
							packet := packets[index]
							packets = append(packets[:index], packets[index+1:]...)
							destination := client
							if packet.fromClient {
								destination = server
							}
							if _, err := destination.receive(packet.data, now); err != nil {
								t.Fatalf("client=%t: %v", destination.handshake.client, err)
							}
							continue
						}
						if len(client.post) == 0 && len(server.post) == 0 && !client.cidRequested && !server.cidRequested {
							break
						}
						next := client.deadline()
						if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
							next = candidate
						}
						if next.IsZero() {
							t.Fatal("CID exchange stalled without a retransmission timer")
						}
						now = next
						for _, s := range []*session{client, server} {
							if err := s.tick(now); err != nil {
								t.Fatal(err)
							}
						}
					}
					for _, fromClient := range []bool{true, false} {
						for _, kind := range []string{"request", "response", "ack"} {
							if immediate && kind == "request" {
								continue
							}
							key := fmt.Sprintf("%t/%s", fromClient, kind)
							if !duplicated[key] || (fault == kind || fault == "all") && !dropped[key] {
								t.Fatalf("fault path not exercised: %s", key)
							}
						}
					}
					for _, s := range []*session{client, server} {
						if s.currentWriteEpoch() != 4 || s.readApplicationEpoch != 4 || s.updating || s.reassembly.buffered != 0 {
							t.Fatal("CID/KeyUpdate exchange did not converge")
						}
						want := maxConnectionIDs - 1
						if immediate {
							want = 0
							if len(s.localCIDs) != 1 {
								t.Fatal("immediate CID did not retire the previous pool")
							}
						}
						if len(s.peerSpareCIDs) != want {
							t.Fatalf("duplicate response grew pool: %d, want %d", len(s.peerSpareCIDs), want)
						}
						s.useSpareCID()
						if err := s.application([]byte("after CID and KeyUpdate")); err != nil {
							t.Fatal(err)
						}
					}
					data := deliverSessionPackets(t, client, server, &packets, now)
					if len(data) != 2 || string(data[0]) != "after CID and KeyUpdate" || !bytes.Equal(data[0], data[1]) {
						t.Fatal("CID recovery lost bidirectional application data")
					}
				})
			}
		}
	}
}
