package dtls13

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type gatedWriteConn struct {
	*handshakePacketConn
	gate     <-chan struct{}
	mu       sync.Mutex
	deadline time.Time
	notify   chan struct{}
	attempts int
	n        int
	err      error
}

func (p *gatedWriteConn) SetWriteDeadline(deadline time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadline = deadline
	if p.notify != nil {
		close(p.notify)
	}
	p.notify = make(chan struct{})
	return nil
}

func (p *gatedWriteConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.attempts++
	if p.gate != nil {
		for {
			p.mu.Lock()
			deadline, notify := p.deadline, p.notify
			p.mu.Unlock()
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return p.n, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(time.Until(deadline))
			select {
			case <-p.gate:
				timer.Stop()
				return p.handshakePacketConn.WriteTo(b, addr)
			case <-timer.C:
				return p.n, os.ErrDeadlineExceeded
			case <-p.closed:
				timer.Stop()
				return 0, net.ErrClosed
			case <-notify:
				timer.Stop()
			}
		}
	}
	if p.err != nil {
		if p.n == -1 {
			return len(b), p.err
		}
		return p.n, p.err
	}
	return p.handshakePacketConn.WriteTo(b, addr)
}

func TestConnWriteDoesNotRetryAmbiguousResult(t *testing.T) {
	for _, n := range []int{1, -1} {
		synctest.Test(t, func(t *testing.T) {
			client, server, p := syntheticConnectionPair(t)
			p.n, p.err = n, os.ErrDeadlineExceeded
			attempts := p.attempts
			if n, err := client.Write([]byte("ambiguous")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("ambiguous write = %d, %v", n, err)
			}
			synctest.Wait()
			if p.attempts != attempts+1 {
				t.Fatal("retried a write that may have sent bytes")
			}
			p.err = nil
			if _, err := client.Write([]byte("recovered")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			if n, err := server.Read(buf); err != nil || string(buf[:n]) != "recovered" {
				t.Fatalf("write error poisoned association: %q, %v", buf[:n], err)
			}
		})
	}
}

func TestTransportWriteCancellationIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		p := &gatedWriteConn{handshakePacketConn: newHandshakePacketConn(10001), gate: gate}
		transport := newPacketTransport(p, nil, nil)
		go transport.writeLoop()
		defer transport.close(net.ErrClosed)
		cancel := make(chan struct{})
		first, second := make(chan error, 1), make(chan error, 1)
		go func() { first <- transport.writeApplication([]byte("cancelled"), p.addr, time.Time{}, nil, cancel) }()
		synctest.Wait()
		go func() { second <- transport.writeApplication([]byte("next peer"), p.addr, time.Time{}, nil, nil) }()
		synctest.Wait()
		close(cancel)
		if err := <-first; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("cancelled write = %v", err)
		}
		synctest.Wait()
		if p.attempts != 2 {
			t.Fatal("cancelled write did not release the shared writer promptly")
		}
		close(gate)
		if err := <-second; err != nil {
			t.Fatalf("cancellation affected the next socket write: %v", err)
		}
	})
}

func TestTransportStaleCancelDoesNotAffectNextWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		p := &gatedWriteConn{handshakePacketConn: newHandshakePacketConn(10001)}
		transport := newPacketTransport(p, nil, nil)
		go transport.writeLoop()
		defer transport.close(net.ErrClosed)
		stale := make(chan struct{})
		if err := transport.writeApplication([]byte("first"), p.addr, time.Time{}, nil, stale); err != nil {
			t.Fatal(err)
		}
		p.gate = gate
		second := make(chan error, 1)
		go func() { second <- transport.writeApplication([]byte("second"), p.addr, time.Time{}, nil, nil) }()
		synctest.Wait()
		close(stale)
		synctest.Wait()
		select {
		case err := <-second:
			t.Fatalf("stale cancel interrupted the next socket write: %v", err)
		default:
		}
		close(gate)
		if err := <-second; err != nil {
			t.Fatal(err)
		}
	})
}

func TestTransportCancelWatcherJoinsBeforeNextWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		p := &gatedWriteConn{handshakePacketConn: newHandshakePacketConn(10001), gate: gate}
		transport := newPacketTransport(p, nil, nil)
		go transport.writeLoop()
		defer transport.close(net.ErrClosed)
		cancel := make(chan struct{})
		first, second := make(chan error, 1), make(chan error, 1)
		go func() { first <- transport.writeApplication([]byte("cancelled"), p.addr, time.Time{}, nil, cancel) }()
		synctest.Wait()
		go func() { second <- transport.writeApplication([]byte("next"), p.addr, time.Time{}, nil, nil) }()
		synctest.Wait()
		close(cancel)
		if err := <-first; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("cancelled write = %v", err)
		}
		synctest.Wait()
		select {
		case err := <-second:
			t.Fatalf("next write finished before its socket attempt: %v", err)
		default:
		}
		close(gate)
		if err := <-second; err != nil {
			t.Fatalf("watcher poke reached the next socket write: %v", err)
		}
	})
}

func TestTransportWriteQueueAndAttemptBounds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		p := &gatedWriteConn{handshakePacketConn: newHandshakePacketConn(10001), gate: gate}
		transport := newPacketTransport(p, nil, nil)
		go transport.writeLoop()
		defer transport.close(net.ErrClosed)
		first, queued := make(chan error, 1), make(chan error, 1)
		go func() { first <- transport.writeApplication([]byte("blocked"), p.addr, time.Time{}, nil, nil) }()
		synctest.Wait()
		cancel := make(chan struct{})
		go func() { queued <- transport.writeApplication([]byte("queued"), p.addr, time.Time{}, nil, cancel) }()
		synctest.Wait()
		close(cancel)
		if err := <-queued; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("queued cancellation = %v", err)
		}
		start := time.Now()
		if err := <-first; !errors.Is(err, errWritePending) || time.Since(start) != time.Second {
			t.Fatalf("socket attempt = %v after %v", err, time.Since(start))
		}
		synctest.Wait()
		if p.attempts != 1 {
			t.Fatal("cancelled queued datagram reached the socket")
		}
		start = time.Now()
		if err := transport.write([]byte("control"), p.addr, start.Add(time.Hour), nil); !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) != time.Second {
			t.Fatalf("control write = %v after %v", err, time.Since(start))
		}
	})
}

// Call within synctest; its barriers also synchronize the fake socket controls.
func syntheticConnectionPair(t *testing.T) (*Conn, *Conn, *gatedWriteConn) {
	t.Helper()
	a, b := handshakeConfigs(t)
	a.CurvePreferences, b.CurvePreferences = []tls.CurveID{tls.X25519}, []tls.CurveID{tls.X25519}
	cp := &gatedWriteConn{handshakePacketConn: newHandshakePacketConn(10001)}
	sp := newHandshakePacketConn(10002)
	cp.send = func(data []byte, _ netip.AddrPort) { sp.incoming <- incomingPacket{data, cp.addr} }
	sp.send = func(data []byte, _ netip.AddrPort) { cp.incoming <- incomingPacket{data, sp.addr} }
	listener, err := Listen(sp, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := Client(context.Background(), cp, listener.Addr(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	accepted, err := listener.AcceptContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	server := accepted.(*Conn)
	synctest.Wait()
	for step := 0; ; step++ {
		if client.session.outbound.complete && len(client.session.post) == 0 && len(server.session.post) == 0 &&
			client.session.ackDeadline.IsZero() && server.session.ackDeadline.IsZero() {
			break
		}
		if step == 20 {
			t.Fatal("initial post-handshake flights did not settle")
		}
		advanceHandshakeClock(initialRetransmit / 4)
	}
	return client, server, cp
}

func TestConnWriteWaitsForCallerDeadline(t *testing.T) {
	for _, mode := range []string{"long", "none", "extend", "clear", "shorten"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server, p := syntheticConnectionPair(t)
				gate := make(chan struct{})
				p.gate = gate
				release := sync.OnceFunc(func() { close(gate) })
				defer release()
				start := time.Now()
				deadline := start.Add(30 * time.Second)
				switch mode {
				case "none":
					deadline = time.Time{}
				case "extend", "clear":
					deadline = start.Add(time.Second)
				}
				if err := client.SetWriteDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				result := make(chan error, 1)
				go func() {
					n, err := client.Write([]byte("one datagram"))
					if err == nil && n != len("one datagram") {
						err = errors.New("short successful write")
					}
					result <- err
				}()
				synctest.Wait()
				advanceHandshakeClock(time.Second / 2)
				switch mode {
				case "extend":
					deadline = start.Add(30 * time.Second)
				case "clear":
					deadline = time.Time{}
				case "shorten":
					deadline = start.Add(750 * time.Millisecond)
				}
				if err := client.SetWriteDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if mode == "shorten" {
					if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) != 750*time.Millisecond {
						t.Fatalf("shortened deadline: %v after %v", err, time.Since(start))
					}
					// Cancellation must interrupt the active socket attempt before its old deadline.
					synctest.Wait()
					if err := client.SetWriteDeadline(time.Time{}); err != nil {
						t.Fatal(err)
					}
				} else {
					advanceHandshakeClock(2 * time.Second)
					select {
					case err := <-result:
						t.Fatalf("write ended before its deadline: %v", err)
					default:
					}
				}
				release()
				if mode != "shorten" {
					if err := <-result; err != nil {
						t.Fatal(err)
					}
				}
				// A marker is a barrier: exactly one application datagram, or none on cancellation.
				synctest.Wait()
				p.gate = nil
				if _, err := client.Write([]byte("marker")); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				if mode != "shorten" {
					if n, err := server.Read(buf); err != nil || string(buf[:n]) != "one datagram" {
						t.Fatalf("application data: %q, %v", buf[:n], err)
					}
				}
				if n, err := server.Read(buf); err != nil || string(buf[:n]) != "marker" {
					t.Fatalf("duplicate or cancelled write arrived: %q, %v", buf[:n], err)
				}
			})
		})
	}
}
