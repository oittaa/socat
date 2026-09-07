//go:build darwin || windows

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPDispatchConnHidesSharedSocket(t *testing.T) {
	conn := &udpDispatchConn{}
	if _, ok := any(conn).(interface{ NetConn() net.Conn }); ok {
		t.Fatal("udpDispatchConn must not expose the shared listener through NetConn")
	}
	if _, ok := any(conn).(syscall.Conn); ok {
		t.Fatal("udpDispatchConn must not expose SyscallConn to relay polling")
	}
}

func TestUDPDispatchConnEmptyPacketIsEOF(t *testing.T) {
	conn := &udpDispatchConn{
		pending:     udpForkPacket{},
		havePending: true,
		done:        make(chan struct{}),
		packets:     make(chan udpForkPacket),
	}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero-length Read = %d, %v; want 0, nil", n, err)
	}
	if !conn.havePending {
		t.Fatal("zero-length Read consumed the pending datagram")
	}
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty datagram Read = %d, %v; want 0, EOF", n, err)
	}
}

func TestUDPDispatchAcceptTimeout(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rejectAt  time.Duration
		notifyAt  time.Duration
		expiresAt time.Duration
	}{
		{name: "idle", expiresAt: 100 * time.Millisecond},
		{name: "notified", rejectAt: 20 * time.Millisecond, notifyAt: 20 * time.Millisecond, expiresAt: 120 * time.Millisecond},
		{name: "unpublished", rejectAt: 20 * time.Millisecond, expiresAt: 120 * time.Millisecond},
		{name: "delayed notification", rejectAt: 20 * time.Millisecond, notifyAt: 110 * time.Millisecond, expiresAt: 120 * time.Millisecond},
		{name: "stale notification", rejectAt: -20 * time.Millisecond, notifyAt: 80 * time.Millisecond, expiresAt: 100 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				l := &udpDispatchListener{
					base:         &udpForkListener{ctx: ctx, acceptTimeout: 100 * time.Millisecond},
					accepts:      make(chan net.Conn),
					done:         make(chan struct{}),
					peerRejected: make(chan struct{}, 1),
				}
				if tc.rejectAt < 0 {
					l.lastReject = time.Now().Add(tc.rejectAt)
				}
				errc := make(chan error, 1)
				go func() {
					_, err := l.Accept()
					errc <- err
				}()
				synctest.Wait()
				elapsed := time.Duration(0)
				if tc.rejectAt > 0 {
					time.Sleep(tc.rejectAt)
					l.mu.Lock()
					l.lastReject = time.Now()
					l.mu.Unlock()
					elapsed = tc.rejectAt
				}
				if tc.notifyAt > 0 {
					time.Sleep(tc.notifyAt - elapsed)
					l.peerRejected <- struct{}{}
					synctest.Wait()
					elapsed = tc.notifyAt
				}
				time.Sleep(tc.expiresAt - elapsed - time.Nanosecond)
				synctest.Wait()
				select {
				case err := <-errc:
					t.Fatalf("accept expired before %s: %v", tc.expiresAt, err)
				default:
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				select {
				case err := <-errc:
					if !errors.Is(err, xio.ErrAcceptTimeout) {
						t.Fatalf("error=%v want ErrAcceptTimeout", err)
					}
				default:
					t.Fatalf("accept did not expire at %s", tc.expiresAt)
				}
			})
		})
	}
}

func TestUDPDispatchRejectedPeerNotification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,reuseaddr,fork,range=10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l := newUDPListenForkListener(&udpForkListener{
		ctx: ctx, pc: pc, spec: spec, g: &xio.Global{Log: logx.New()},
	}).(*udpDispatchListener)
	t.Cleanup(func() { _ = l.Close() })
	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("refused")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.peerRejected:
	case <-ctx.Done():
		t.Fatal("refused datagram did not notify Accept")
	}
	l.mu.Lock()
	last := l.lastReject
	l.mu.Unlock()
	if last.IsZero() {
		t.Fatal("refused datagram did not record its rejection time")
	}
	select {
	case <-l.accepts:
		t.Fatal("refused peer was accepted")
	default:
	}
}
