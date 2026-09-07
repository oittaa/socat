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

func TestUDPDispatchShouldRestartAcceptTimeout(t *testing.T) {
	l := &udpDispatchListener{
		base:         &udpForkListener{acceptTimeout: 100 * time.Millisecond},
		peerRejected: make(chan struct{}, 1),
	}
	if l.shouldRestartAcceptTimeout() {
		t.Fatal("idle listener restarted accept-timeout")
	}
	l.peerRejected <- struct{}{}
	if !l.shouldRestartAcceptTimeout() {
		t.Fatal("queued reject did not restart accept-timeout")
	}
	if l.shouldRestartAcceptTimeout() {
		t.Fatal("queued reject restarted accept-timeout twice")
	}
	l.lastReject.Store(time.Now().UnixNano())
	if !l.shouldRestartAcceptTimeout() {
		t.Fatal("recent reject did not restart accept-timeout")
	}
	l.lastReject.Store(time.Now().Add(-time.Second).UnixNano())
	if l.shouldRestartAcceptTimeout() {
		t.Fatal("stale reject restarted accept-timeout")
	}
}

func TestUDPDispatchAcceptTimeoutRestartsFromLastReject(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := &udpDispatchListener{
			base:         &udpForkListener{ctx: context.Background(), acceptTimeout: 100 * time.Millisecond},
			accepts:      make(chan net.Conn),
			done:         make(chan struct{}),
			peerRejected: make(chan struct{}, 1),
		}
		errc := make(chan error, 1)
		go func() {
			_, err := l.Accept()
			errc <- err
		}()
		synctest.Wait()
		time.Sleep(20 * time.Millisecond)
		synctest.Wait()
		l.lastReject.Store(time.Now().UnixNano())
		time.Sleep(80 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-errc:
			t.Fatalf("accept returned while last reject was recent: %v", err)
		default:
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-errc:
			if !errors.Is(err, xio.ErrAcceptTimeout) {
				t.Fatalf("error=%v want ErrAcceptTimeout", err)
			}
		default:
			t.Fatal("accept did not time out after last reject aged out")
		}
	})
}
