package dtls13

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"
)

func TestCIDListenerAuthenticationRetirementAndCleanup(t *testing.T) {
	for _, ending := range []string{"close", "malformed"} {
		t.Run(ending, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := handshakeConfigs(t)
				serverWire := newHandshakePacketConn(2200)
				clientWires := []*handshakePacketConn{newHandshakePacketConn(2201), newHandshakePacketConn(2202)}
				var held []incomingPacket
				hold := false
				serverWire.send = func(data []byte, peer netip.AddrPort) {
					if hold {
						held = append(held, incomingPacket{data, peer})
						return
					}
					for _, wire := range clientWires {
						if wire.addr == peer {
							wire.incoming <- incomingPacket{data, serverWire.addr}
						}
					}
				}
				for _, wire := range clientWires {
					wire.send = func(data []byte, _ netip.AddrPort) {
						serverWire.incoming <- incomingPacket{data, wire.addr}
					}
				}
				listener, err := Listen(serverWire, b)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()
				var clients, servers []*Conn
				for _, wire := range clientWires {
					client, err := Client(context.Background(), wire, serverWire.LocalAddr(), a)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = client.Close() }()
					peer, err := listener.Accept()
					if err != nil {
						t.Fatal(err)
					}
					clients, servers = append(clients, client), append(servers, peer.(*Conn))
				}
				synctest.Wait()
				// Quiescence permits inspection of session state; route maps also
				// use their production lock. No event-loop state is mutated here.
				routes := func(c *Conn) [][]byte {
					listener.mu.Lock()
					defer listener.mu.Unlock()
					var ids [][]byte
					for id, owner := range listener.cids {
						if owner == c {
							ids = append(ids, []byte(id))
						}
					}
					return ids
				}
				old, unrelated := routes(servers[0]), routes(servers[1])
				if len(old) != 5 || len(unrelated) != 5 {
					t.Fatalf("proactive request routes: %d, %d; want 5 each", len(old), len(unrelated))
				}
				hold = true
				rotated := make(chan error, 1)
				go func() { rotated <- servers[0].RotateConnectionID() }()
				synctest.Wait()
				pending := routes(servers[0])
				var replacement []byte
				for _, id := range pending {
					if !containsCID(old, id) {
						replacement = id
					}
				}
				if len(pending) != len(old)+1 || len(replacement) == 0 || len(held) != 1 {
					t.Fatal("rotation did not retain old routes until authenticated use")
				}
				protect := func(cid []byte, typ byte, body []byte) []byte {
					s := clients[0].session
					epoch := s.currentWriteEpoch()
					w := s.write[epoch]
					packet, err := w.keys.encodeRecord(recordNumber{epoch, w.sequence}, cid, typ, body, 0)
					if err != nil {
						t.Fatal(err)
					}
					return packet
				}
				forged := protect(replacement, contentData, []byte("forged"))
				forged[len(forged)-1] ^= 1
				serverWire.incoming <- incomingPacket{forged, clientWires[0].addr}
				synctest.Wait()
				if len(routes(servers[0])) != len(pending) || servers[0].session.read[3].failures != 1 {
					t.Fatal("forged use of new CID retired routes or bypassed authentication")
				}
				hold = false
				clientWires[0].incoming <- incomingPacket{held[0].data, serverWire.addr}
				if err := <-rotated; err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				ids := routes(servers[0])
				if len(ids) != 1 || !bytes.Equal(ids[0], replacement) {
					t.Fatal("authenticated new-CID ACK did not retire all previous aliases")
				}
				// A retired alias cannot find this association from a new address.
				retired := protect(old[0], contentData, []byte("retired"))
				serverWire.incoming <- incomingPacket{retired, netip.MustParseAddrPort("127.0.0.1:2299")}
				// A CID belonging to another association must not share its keys.
				crossed := protect(unrelated[0], contentData, []byte("wrong association"))
				serverWire.incoming <- incomingPacket{crossed, clientWires[0].addr}
				synctest.Wait()
				if servers[0].session.path.probe != nil || len(routes(servers[1])) != len(unrelated) || servers[1].session.read[3].failures != 1 {
					t.Fatal("CID routing crossed associations or accepted a retired alias")
				}
				marker := func(client, server *Conn) {
					if _, err := client.Write([]byte("marker")); err != nil {
						t.Fatal(err)
					}
					buffer := make([]byte, 64)
					if n, err := server.Read(buffer); err != nil || string(buffer[:n]) != "marker" {
						t.Fatalf("routing/authentication barrier: %q, %v", buffer[:n], err)
					}
					synctest.Wait()
				}
				marker(clients[0], servers[0])
				marker(clients[1], servers[1])
				if err := listener.setCIDs(servers[0], unrelated); err == nil || len(routes(servers[0])) != 1 || len(routes(servers[1])) != len(unrelated) {
					t.Fatal("CID collision did not preserve both route tables")
				}
				// End with multiple live aliases and an unacknowledged rotation.
				hold, held = true, nil
				go func() { rotated <- servers[0].RotateConnectionID() }()
				synctest.Wait()
				if len(routes(servers[0])) != 2 {
					t.Fatal("cleanup test did not retain multiple live aliases")
				}
				hold = false
				if ending == "close" {
					if err := servers[0].Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					seq := uint16(clients[0].session.handshake.sequence)
					fragment := cidWireFragment(msgNewConnectionID, seq+1, 65538, 0, []byte{0})
					serverWire.incoming <- incomingPacket{protect(replacement, contentHandshake, fragment), clientWires[0].addr}
					synctest.Wait()
					if listener.fragments.used.Load() == 0 {
						t.Fatal("cleanup test did not reserve fragment memory")
					}
					wire := cidWireFragment(msgNewConnectionID, seq, 1, 0, []byte{0})
					// The modeled peer sent one record outside Conn.Write; advance
					// only the explicit wire number so the next record is not a replay.
					s := clients[0].session
					w := s.write[s.currentWriteEpoch()]
					fatal, err := w.keys.encodeRecord(recordNumber{s.currentWriteEpoch(), w.sequence + 1}, replacement, contentHandshake, wire, 0)
					if err != nil {
						t.Fatal(err)
					}
					serverWire.incoming <- incomingPacket{fatal, clientWires[0].addr}
					<-servers[0].done
					<-clients[0].done
					if !errors.Is(servers[0].failure(), errDecode) || !errors.Is(clients[0].failure(), errDecode) {
						t.Fatalf("malformed CID did not emit fatal decode_error: server=%v, client=%v", servers[0].failure(), clients[0].failure())
					}
				}
				if err := <-rotated; err == nil {
					t.Fatal("unacknowledged rotation succeeded after association shutdown")
				}
				synctest.Wait()
				if len(routes(servers[0])) != 0 || len(routes(servers[1])) != len(unrelated) || listener.packets.used.Load() != 0 || listener.fragments.used.Load() != 0 {
					t.Fatal("association cleanup leaked aliases/budgets or removed unrelated routes")
				}
				marker(clients[1], servers[1])
			})
		})
	}
}
