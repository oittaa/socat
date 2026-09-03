package netopen

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func concurrentCloses(t *testing.T, closeFn func() error, n int) []error {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = closeFn()
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

func TestUDPSessionConnConcurrentCloseOwnedOnce(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	u := &udpSessionConn{conn: pc}
	errs := concurrentCloses(t, u.Close, 32)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Close[%d]=%v", i, err)
		}
	}
	if err := u.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(time.Millisecond)); err == nil {
		t.Fatal("owned socket still usable after Close")
	}
}

func TestUDPSessionConnOneShotCloseDoesNotCloseParent(t *testing.T) {
	parent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	u := &udpSessionConn{pc: parent, oneShot: true}
	errs := concurrentCloses(t, u.Close, 16)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Close[%d]=%v", i, err)
		}
	}
	if err := parent.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("one-shot Close closed parent: %v", err)
	}
}

func TestUDPSessionConnExclusiveHandoffReleaseOnce(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var releases atomic.Int32
	u := &udpSessionConn{
		pc:         pc,
		ownsListen: true,
		releaseListen: func() {
			releases.Add(1)
		},
	}
	errs := concurrentCloses(t, u.Close, 32)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Close[%d]=%v", i, err)
		}
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("releaseListen calls=%d want 1", got)
	}
	if err := pc.SetReadDeadline(time.Now().Add(time.Millisecond)); err == nil {
		t.Fatal("handed-off listen socket still usable after Close")
	}
}

func TestUDPSessionConnCloseVsDeadline(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	u := &udpSessionConn{conn: pc}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_ = u.Close()
	}()
	go func() {
		defer wg.Done()
		<-start
		_ = u.SetReadDeadline(time.Now().Add(time.Millisecond))
		_ = u.SetWriteDeadline(time.Now().Add(time.Millisecond))
	}()
	close(start)
	wg.Wait()
	if err := u.Close(); err != nil {
		t.Fatalf("final Close: %v", err)
	}
}
