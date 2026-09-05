package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oittaa/socat/internal/testcert"
)

// Channel I/O lets synctest advance the actual connection timers deterministically.
type handshakePacketConn struct {
	addr     netip.AddrPort
	incoming chan incomingPacket
	closed   chan struct{}
	once     sync.Once
	send     func([]byte, netip.AddrPort)
}

func newHandshakePacketConn(port uint16) *handshakePacketConn {
	return &handshakePacketConn{addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
		incoming: make(chan incomingPacket, 256), closed: make(chan struct{})}
}

func (p *handshakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case packet := <-p.incoming:
		return copy(b, packet.data), net.UDPAddrFromAddrPort(packet.peer), nil
	case <-p.closed:
		return 0, nil, net.ErrClosed
	}
}

func (p *handshakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	peer, err := udpAddress(addr)
	if err != nil {
		return 0, err
	}
	if p.send != nil {
		p.send(bytes.Clone(b), peer)
	}
	return len(b), nil
}

func (p *handshakePacketConn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *handshakePacketConn) LocalAddr() net.Addr              { return net.UDPAddrFromAddrPort(p.addr) }
func (p *handshakePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (p *handshakePacketConn) SetReadDeadline(time.Time) error {
	return errors.New("association timeout must not set the transport read deadline")
}
func (p *handshakePacketConn) SetDeadline(t time.Time) error { return p.SetReadDeadline(t) }

func advanceHandshakeClock(d time.Duration) {
	<-time.After(d)
	synctest.Wait()
}

func checkHandshakeReadTimeout(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrHandshakeReadTimeout) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("handshake receive timeout = %v", err)
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("not a timeout error: %v", err)
	}
	var retryable interface{ Retryable() bool }
	if errors.As(err, &retryable) {
		t.Fatalf("handshake failure exposes stream retry semantics: %v", err)
	}
}

func TestClientHandshakeReceiveTimeout(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		read, absolute, parent time.Duration
		disableAbsolute        bool
		want                   error
		elapsed                time.Duration
	}{
		{"receive", 2 * time.Second, 10 * time.Second, 20 * time.Second, false, ErrHandshakeReadTimeout, 2 * time.Second},
		{"absolute", 4 * time.Second, 2 * time.Second, 20 * time.Second, false, context.DeadlineExceeded, 2 * time.Second},
		{"receive_disabled", 0, 2 * time.Second, 20 * time.Second, false, context.DeadlineExceeded, 2 * time.Second},
		{"absolute_disabled", 2 * time.Second, 0, 20 * time.Second, true, ErrHandshakeReadTimeout, 2 * time.Second},
		{"both_disabled", 0, 0, 4 * time.Second, true, context.DeadlineExceeded, 4 * time.Second},
		{"parent", 4 * time.Second, 10 * time.Second, 2 * time.Second, false, context.DeadlineExceeded, 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, _ := handshakeConfigs(t)
				config.CurvePreferences = []tls.CurveID{tls.X25519}
				config.HandshakeReadTimeout, config.HandshakeTimeout = tc.read, tc.absolute
				config.DisableHandshakeTimeout = tc.disableAbsolute
				p := newHandshakePacketConn(10001)
				sent := 0
				p.send = func([]byte, netip.AddrPort) { sent++ }
				ctx, cancel := context.WithTimeout(context.Background(), tc.parent)
				defer cancel()
				start := time.Now()
				_, err := Client(ctx, p, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:10002")), config)
				synctest.Wait()
				if !errors.Is(err, tc.want) || time.Since(start) != tc.elapsed {
					t.Fatalf("Client = %v after %v; want %v after %v", err, time.Since(start), tc.want, tc.elapsed)
				}
				if tc.want == ErrHandshakeReadTimeout {
					checkHandshakeReadTimeout(t, err)
				}
				if sent < 2 {
					t.Fatal("test did not exercise outgoing retransmission before timeout")
				}
				if _, err := p.WriteTo([]byte("closed"), p.LocalAddr()); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("failed client retained its transport: %v", err)
				}
			})
		})
	}
}

func handshakeFragmentPacket(t *testing.T, typ byte, offset int) []byte {
	t.Helper()
	m := handshakeMessage{typ: typ, body: make([]byte, 100)}
	fragment, err := m.fragment(offset, 1)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := encodePlainRecord(contentHandshake, uint64(offset), fragment)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestHandshakeReceiveActivity(t *testing.T) {
	for _, kind := range []string{"fragments", "duplicate", "ack", "wrong_peer", "wrong_cid", "malformed", "absolute_bound"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, _ := handshakeConfigs(t)
				config.HandshakeReadTimeout = time.Second
				config.HandshakeTimeout = 10 * time.Second
				if kind == "absolute_bound" {
					config.HandshakeTimeout = 2 * time.Second
				}
				p := newHandshakePacketConn(10001)
				peer := netip.MustParseAddrPort("127.0.0.1:10002")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan error, 1)
				start := time.Now()
				go func() { _, err := Client(ctx, p, net.UDPAddrFromAddrPort(peer), config); result <- err }()
				synctest.Wait()
				ignored := kind == "wrong_peer" || kind == "wrong_cid" || kind == "malformed"
				for i := range 6 {
					advanceHandshakeClock(time.Second / 4)
					packet := handshakeFragmentPacket(t, msgServerHello, i)
					from := peer
					switch kind {
					case "duplicate", "absolute_bound":
						packet = handshakeFragmentPacket(t, msgServerHello, 0)
					case "ack":
						var err error
						packet, err = encodePlainRecord(contentACK, 0, []byte{0, 0})
						if err != nil {
							t.Fatal(err)
						}
					case "wrong_peer":
						from = netip.MustParseAddrPort("127.0.0.1:10003")
					case "wrong_cid":
						// Unified header, eight-byte unknown CID, one-byte sequence, 16-byte tag.
						packet = append([]byte{0x32}, make([]byte, 8+1+16)...)
					case "malformed":
						packet = []byte{0xff}
					}
					p.incoming <- incomingPacket{packet, from}
					synctest.Wait()
					if ignored && i == 2 {
						break
					}
					select {
					case err := <-result:
						t.Fatalf("received %s but handshake expired after %v: %v", kind, time.Since(start), err)
					default:
					}
				}
				err := <-result
				wantElapsed := 2500 * time.Millisecond
				if ignored {
					wantElapsed = time.Second
				}
				if kind == "absolute_bound" {
					wantElapsed = 2 * time.Second
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("absolute deadline did not bound repeated reception: %v", err)
					}
				} else {
					checkHandshakeReadTimeout(t, err)
				}
				if time.Since(start) != wantElapsed {
					t.Fatalf("%s timeout after %v; want %v", kind, time.Since(start), wantElapsed)
				}
			})
		})
	}
}

func TestListenerHandshakeReceiveTimeoutIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := handshakeConfigs(t)
		a.HandshakeReadTimeout, b.HandshakeReadTimeout = time.Second, time.Second
		clientPacket, serverPacket := newHandshakePacketConn(10001), newHandshakePacketConn(10002)
		clientPacket.send = func(data []byte, _ netip.AddrPort) {
			serverPacket.incoming <- incomingPacket{data, clientPacket.addr}
		}
		serverPacket.send = func(data []byte, peer netip.AddrPort) {
			if peer == clientPacket.addr {
				clientPacket.incoming <- incomingPacket{data, serverPacket.addr}
			}
		}
		listener, err := Listen(serverPacket, b)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = listener.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client, err := Client(ctx, clientPacket, listener.Addr(), a)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		server, err := listener.AcceptContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stalledPeer := netip.MustParseAddrPort("127.0.0.1:10003")
		serverPacket.incoming <- incomingPacket{handshakeFragmentPacket(t, msgClientHello, 0), stalledPeer}
		synctest.Wait()
		listener.mu.Lock()
		stalled := listener.handshakes[stalledPeer]
		listener.mu.Unlock()
		if stalled == nil || listener.fragments.used.Load() == 0 {
			t.Fatal("partial ClientHello did not create a pending association")
		}
		for range 3 {
			advanceHandshakeClock(time.Second / 4)
			if _, err := client.Write([]byte("other association")); err != nil {
				t.Fatal(err)
			}
			if _, err := server.Read(make([]byte, 64)); err != nil {
				t.Fatal(err)
			}
			// Waking the stalled association must not refresh its receive wait.
			if err := stalled.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		<-stalled.done
		checkHandshakeReadTimeout(t, stalled.failure())
		synctest.Wait()
		listener.mu.Lock()
		remaining, pending, ids := len(listener.connections), len(listener.handshakes), len(listener.cids)
		listener.mu.Unlock()
		if remaining != 1 || pending != 0 || ids == 0 || listener.fragments.used.Load() != 0 || listener.packets.used.Load() != 0 {
			t.Fatalf("association cleanup: connections=%d pending=%d CIDs=%d fragments=%d packets=%d",
				remaining, pending, ids, listener.fragments.used.Load(), listener.packets.used.Load())
		}
		// Neither the completed associations nor the shared transport expire while idle.
		advanceHandshakeClock(2 * time.Second)
		if _, err := server.Write([]byte("still alive")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		if n, err := client.Read(buf); err != nil || string(buf[:n]) != "still alive" {
			t.Fatalf("established association after timeout: %q, %v", buf[:n], err)
		}
		// A new partial handshake still reaches admission after the old one is removed.
		serverPacket.incoming <- incomingPacket{handshakeFragmentPacket(t, msgClientHello, 0), stalledPeer}
		synctest.Wait()
		listener.mu.Lock()
		replacement := listener.handshakes[stalledPeer]
		listener.mu.Unlock()
		if replacement == nil || replacement == stalled {
			t.Fatal("listener did not admit a fresh association after timeout")
		}
	})
}

func TestHandshakeReceiveTimeoutAllowsLargeFragmentedCertificate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca, err := testcert.NewAuthority("fragmented certificate CA")
		if err != nil {
			t.Fatal(err)
		}
		names := []string{"localhost"}
		for i := range 200 {
			names = append(names, fmt.Sprintf("host%03d.example.test", i))
		}
		leaf, err := ca.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, names)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.Cert)
		a := &Config{ServerName: "localhost", RootCAs: roots, MTU: 256, DisableMigration: true,
			CurvePreferences: []tls.CurveID{tls.X25519}, HandshakeReadTimeout: time.Second}
		b := &Config{Certificates: []tls.Certificate{leaf.TLS()}, MTU: 256, DisableMigration: true,
			HandshakeReadTimeout: time.Second}
		clientPacket, serverPacket := newHandshakePacketConn(10001), newHandshakePacketConn(10002)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		clientPacket.send = func(data []byte, _ netip.AddrPort) {
			serverPacket.incoming <- incomingPacket{data, clientPacket.addr}
		}
		wire := make(chan []byte, 256)
		serverPacket.send = func(data []byte, _ netip.AddrPort) { wire <- data }
		go func() {
			for {
				select {
				case data := <-wire:
					// Pace the wire, not WriteTo: certificate reassembly spans many receive waits.
					select {
					case <-time.After(100 * time.Millisecond):
						clientPacket.incoming <- incomingPacket{data, serverPacket.addr}
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		listener, err := Listen(serverPacket, b)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = listener.Close() }()
		start := time.Now()
		client, err := Client(ctx, clientPacket, listener.Addr(), a)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		server, err := listener.AcceptContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(start) <= 2*a.HandshakeReadTimeout {
			t.Fatal("fragmented handshake did not span multiple receive intervals")
		}
		if _, err := client.Write([]byte("verified")); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 64)
		if n, err := server.Read(buffer); err != nil || string(buffer[:n]) != "verified" {
			t.Fatalf("application data after fragmented handshake = %q, %v", buffer[:n], err)
		}
	})
}
