package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Complete the cookie exchange, then stop consuming the server's certificate flight.
func startStalledCookieHandshake(t *testing.T, l *Listener, packet *handshakePacketConn, config *Config, peer netip.AddrPort, wire <-chan []byte) *Conn {
	t.Helper()
	client, err := newClientSession(config, func(data []byte) error {
		packet.incoming <- incomingPacket{data, peer}
		return nil
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 1000; step++ {
		synctest.Wait()
		l.mu.Lock()
		c := l.handshakes[peer]
		l.mu.Unlock()
		if c != nil {
			return c
		}
		select {
		case data := <-wire:
			if _, err := client.receive(data, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-time.After(initialRetransmit / 4):
			if err := client.tick(time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Fatal("cookie exchange did not reach admission")
	return nil
}

func TestCookieAdmissionLossReorderAndEviction(t *testing.T) {
	for _, mode := range []string{"loss_reorder", "eviction", "fragmented_retry"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := handshakeConfigs(t)
				a.MTU, b.MTU = 256, 256
				for i := range 40 {
					a.NextProtos = append(a.NextProtos, fmt.Sprintf("%03d%s", i, strings.Repeat("x", 197)))
				}
				b.NextProtos = a.NextProtos[:1]
				packet := newHandshakePacketConn(10002)
				peer := netip.MustParseAddrPort("127.0.0.1:10001")
				wire := make(chan []byte, 256)
				var received, sent atomic.Int64
				var l *Listener
				droppedRetry := false
				packet.send = func(data []byte, _ netip.AddrPort) {
					sent.Add(int64(len(data)))
					l.mu.Lock()
					unvalidated := len(l.connections) == 0
					l.mu.Unlock()
					if unvalidated && sent.Load() > 3*received.Load() {
						t.Error("unvalidated retry traffic exceeded 3x amplification")
					}
					r, _, err := parseRecord(data, 8)
					if err == nil && !r.encrypted && r.typ == contentHandshake {
						f, _, err := parseFragment(r.body)
						if err == nil && f.sequence == 0 && !droppedRetry && mode != "eviction" {
							droppedRetry = true
							return
						}
					}
					wire <- data
				}
				var err error
				l, err = Listen(packet, b)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = l.Close() }()
				h, messages, err := newClientHandshake(a)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "fragmented_retry" {
					var identities []string
					for i := range 100 {
						identities = append(identities, fmt.Sprintf("ticket-%d", i))
					}
					h.hello.extensions[extPSKModes] = []byte{1, 1}
					h.hello.extensions[extPreSharedKey] = testPSKOffer(identities...)
					messages[0].body, err = h.hello.marshal()
					if err != nil {
						t.Fatal(err)
					}
					h.firstHello, err = messages[0].transcript()
					if err != nil {
						t.Fatal(err)
					}
				}
				var outgoing [][]byte
				client := newSession(h.handshakeState, h.handle, func(data []byte) error {
					outgoing = append(outgoing, bytes.Clone(data))
					return nil
				})
				if err := client.startFlight(messages, time.Now()); err != nil {
					t.Fatal(err)
				}
				droppedHello := [2]bool{}
				evicted := false
				for step := 0; ; step++ {
					if step == 2000 {
						t.Fatal("cookie handshake exceeded event bound")
					}
					slices.Reverse(outgoing)
					for _, data := range outgoing {
						r, _, err := parseRecord(data, 8)
						if err != nil {
							t.Fatal(err)
						}
						if !r.encrypted && r.typ == contentHandshake {
							f, _, err := parseFragment(r.body)
							if err != nil {
								t.Fatal(err)
							}
							if f.sequence < 2 && !droppedHello[f.sequence] && mode != "eviction" {
								droppedHello[f.sequence] = true
								continue
							}
							if f.sequence == 1 && mode == "eviction" && !evicted {
								fragment, _ := (handshakeMessage{typ: msgClientHello, body: make([]byte, 4096)}).fragment(0, 1)
								junk, _ := encodePlainRecord(contentHandshake, 0, fragment)
								for port := uint16(11000); port < 11000+maxHelloEntries; port++ {
									packet.incoming <- incomingPacket{junk, netip.AddrPortFrom(peer.Addr(), port)}
									synctest.Wait()
								}
								l.mu.Lock()
								cached, connections := l.hellos[peer] != nil, len(l.connections)
								l.mu.Unlock()
								if cached || connections != 0 {
									t.Fatal("spoofed hellos did not evict the cache without allocating associations")
								}
								evicted = true
							}
						}
						received.Add(int64(len(data)))
						packet.incoming <- incomingPacket{data, peer}
					}
					outgoing = nil
					synctest.Wait()
					var incoming [][]byte
					for len(wire) != 0 {
						incoming = append(incoming, <-wire)
					}
					slices.Reverse(incoming)
					for _, data := range incoming {
						if _, err := client.receive(data, time.Now()); err != nil {
							t.Fatal(err)
						}
					}
					if client.handshake.complete && client.outbound.complete {
						break
					}
					if len(outgoing) == 0 && len(incoming) == 0 {
						advanceHandshakeClock(initialRetransmit / 4)
						if err := client.tick(time.Now()); err != nil {
							t.Fatal(err)
						}
					}
				}
				synctest.Wait()
				if mode == "eviction" && !evicted || mode != "eviction" && (!droppedHello[0] || !droppedHello[1] || !droppedRetry) {
					t.Fatal("fault injection did not exercise the selected case")
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				server, err := l.AcceptContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := client.application([]byte("authenticated after retry")); err != nil {
					t.Fatal(err)
				}
				for _, data := range outgoing {
					packet.incoming <- incomingPacket{data, peer}
				}
				buf := make([]byte, 64)
				if n, err := server.Read(buf); err != nil || string(buf[:n]) != "authenticated after retry" {
					t.Fatalf("application after cookie admission: %q, %v", buf[:n], err)
				}
			})
		})
	}
}

func TestCookieCacheExpiryAndStopAccept(t *testing.T) {
	for _, mode := range []string{"absolute", "receive", "stop", "malformed_tail"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, config := handshakeConfigs(t)
				config.HandshakeTimeout = 2 * time.Second
				if mode == "receive" {
					config.DisableHandshakeTimeout = true
					config.HandshakeReadTimeout = 2 * time.Second
				}
				packet := newHandshakePacketConn(10002)
				l, err := Listen(packet, config)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = l.Close() }()
				synctest.Wait()
				fragment, _ := (handshakeMessage{typ: msgClientHello, body: make([]byte, 4096)}).fragment(0, 1)
				if mode == "malformed_tail" {
					fragment = append(fragment, 0xff)
				}
				data, _ := encodePlainRecord(contentHandshake, 0, fragment)
				peer := netip.MustParseAddrPort("192.0.2.1:10001")
				packet.incoming <- incomingPacket{data, peer}
				synctest.Wait()
				l.mu.Lock()
				entries := len(l.hellos)
				l.mu.Unlock()
				if entries != 1 {
					t.Fatal("partial ClientHello was not cached")
				}
				if mode == "stop" {
					_ = l.StopAccept()
					packet.incoming <- incomingPacket{data, peer}
					synctest.Wait()
				} else {
					advanceHandshakeClock(2 * time.Second)
				}
				l.mu.Lock()
				defer l.mu.Unlock()
				if len(l.hellos) != 0 || l.helloBudget.used.Load() != 0 || len(l.connections) != 0 || len(l.cids) != 0 {
					t.Fatal("expired or stopped cookie cache retained resources")
				}
			})
		})
	}
}

func TestCookieRetryACKCannotSuppressHello(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := handshakeConfigs(t)
		a.CurvePreferences, b.CurvePreferences = []tls.CurveID{tls.X25519}, []tls.CurveID{tls.X25519}
		packet := newHandshakePacketConn(10002)
		peer := netip.MustParseAddrPort("127.0.0.1:10001")
		wire := make(chan []byte, 32)
		packet.send = func(data []byte, _ netip.AddrPort) { wire <- data }
		l, err := Listen(packet, b)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		client, err := newClientSession(a, func(data []byte) error {
			packet.incoming <- incomingPacket{data, peer}
			return nil
		}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		first, _, err := parseRecord(<-wire, 8)
		if err != nil {
			t.Fatal(err)
		}
		ack, _ := encodeACK([]recordNumber{first.number})
		data, _ := encodePlainRecord(contentACK, 1, ack)
		packet.incoming <- incomingPacket{data, peer}
		synctest.Wait()
		l.mu.Lock()
		complete := l.hellos[peer].session.outbound.complete
		l.mu.Unlock()
		if !complete {
			t.Fatal("forged plaintext ACK did not complete the retry flight")
		}
		if err := client.transmitFlight(time.Now()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case data := <-wire:
			retry, _, err := parseRecord(data, 8)
			if err != nil || retry.number.sequence <= first.number.sequence || !bytes.Equal(retry.body, first.body) {
				t.Fatal("ClientHello retransmission did not recover the same retry with a fresh record number")
			}
		default:
			t.Fatal("forged ACK suppressed the retry")
		}
	})
}

func TestCookieRetryBookkeepingBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := handshakeConfigs(t)
		a.MTU, b.MTU = 256, 256
		packet := newHandshakePacketConn(10002)
		peer := netip.MustParseAddrPort("127.0.0.1:10001")
		wire := make(chan []byte, 32)
		packet.send = func(data []byte, _ netip.AddrPort) { wire <- data }
		l, err := Listen(packet, b)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		h, messages, err := newClientHandshake(a)
		if err != nil {
			t.Fatal(err)
		}
		var identities []string
		for i := range 1000 {
			identities = append(identities, fmt.Sprint(i))
		}
		h.hello.extensions[extPSKModes] = []byte{1, 1}
		h.hello.extensions[extPreSharedKey] = testPSKOffer(identities...)
		messages[0].body, err = h.hello.marshal()
		if err != nil {
			t.Fatal(err)
		}
		for offset := 0; offset < len(messages[0].body); {
			n := min(200, len(messages[0].body)-offset)
			fragment, _ := messages[0].fragment(offset, n)
			data, _ := encodePlainRecord(contentHandshake, uint64(offset), fragment)
			packet.incoming <- incomingPacket{data, peer}
			synctest.Wait()
			offset += n
			// Discard partial-flight ACKs; retain the final retry burst.
			if offset < len(messages[0].body) {
				for len(wire) != 0 {
					<-wire
				}
			}
		}
		for attempt := range 2 * maxHelloRecords {
			var first *recordNumber
			for len(wire) != 0 {
				r, _, err := parseRecord(<-wire, 8)
				if err != nil {
					t.Fatal(err)
				}
				if r.typ == contentHandshake && first == nil {
					first = &r.number
				}
			}
			if first == nil {
				t.Fatal("retry flight stopped before exercising its bookkeeping bound")
			}
			// Acknowledge just one new fragment to trigger repeated partial bursts.
			ack, _ := encodeACK([]recordNumber{*first})
			data, _ := encodePlainRecord(contentACK, uint64(1000+attempt), ack)
			packet.incoming <- incomingPacket{data, peer}
			synctest.Wait()
			l.mu.Lock()
			p := l.hellos[peer]
			if p == nil {
				used, connections := l.helloBudget.used.Load(), len(l.connections)
				l.mu.Unlock()
				if used != 0 || connections != 0 {
					t.Fatal("retry eviction leaked resources")
				}
				return
			}
			count := len(p.session.outbound.sent)
			l.mu.Unlock()
			if count > maxHelloRecords {
				t.Fatalf("partial ACKs grew unvalidated retransmission bookkeeping to %d records", count)
			}
		}
		t.Fatal("retry bookkeeping did not reach its bound")
	})
}

func TestCookieAdmissionKeepsVerifiedHandshakeBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := handshakeConfigs(t)
		a.CurvePreferences, b.CurvePreferences = []tls.CurveID{tls.X25519}, []tls.CurveID{tls.X25519}
		packet := newHandshakePacketConn(10002)
		wire := make(map[netip.AddrPort]chan []byte)
		packet.send = func(data []byte, peer netip.AddrPort) { wire[peer] <- data }
		l, err := Listen(packet, b)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		for port := uint16(11000); port < 11017; port++ {
			synctest.Wait()
			peer := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
			wire[peer] = make(chan []byte, 32)
			if port < 11016 {
				startStalledCookieHandshake(t, l, packet, a, peer, wire[peer])
				continue
			}
			// A seventeenth valid cookie is rejected without consuming another slot.
			client, err := newClientSession(a, func(data []byte) error {
				packet.incoming <- incomingPacket{data, peer}
				return nil
			}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if _, err := client.receive(<-wire[peer], time.Now()); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			l.mu.Lock()
			defer l.mu.Unlock()
			if len(l.connections) != 16 || len(l.handshakes) != 16 || l.handshakes[peer] != nil {
				t.Fatal("cookie validation bypassed the pending handshake bound")
			}
		}
	})
}
