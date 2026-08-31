package xio

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
)

type closeOnlyListener struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseOnlyListener() *closeOnlyListener {
	return &closeOnlyListener{closed: make(chan struct{})}
}

func (l *closeOnlyListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *closeOnlyListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *closeOnlyListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAcceptWithTimeoutWithoutDeadlineSupport(t *testing.T) {
	ln := newCloseOnlyListener()
	start := time.Now()
	_, err := AcceptWithTimeout(context.Background(), ln, 30*time.Millisecond)
	if !errors.Is(err, ErrAcceptTimeout) {
		t.Fatalf("error=%v want ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("accept timeout took %s", elapsed)
	}
}

type oneConnListener struct {
	conn        net.Conn
	closed      chan struct{}
	waiting     chan struct{}
	acceptErr   error
	once        sync.Once
	waitingOnce sync.Once
	taken       atomic.Bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.taken.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	if l.waiting != nil {
		l.waitingOnce.Do(func() { close(l.waiting) })
	}
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestForkAcceptTimeoutWaitsForActiveSession(t *testing.T) {
	accepted, peer := net.Pipe()
	t.Cleanup(func() { _ = accepted.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	ln := &oneConnListener{conn: accepted, closed: make(chan struct{})}
	opened := &Opened{AcceptTimeout: 30 * time.Millisecond}
	g := &Global{Log: logx.New()}
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- opened.forEachAccepted(context.Background(), ln, g, false, func(net.Conn, *Global) {
			close(started)
			<-release
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("accepted session did not start")
	}
	select {
	case err := <-result:
		t.Fatalf("accept loop returned before active session finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, ErrAcceptTimeout) {
			t.Fatalf("error=%v want ErrAcceptTimeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("accept loop did not return after active session finished")
	}
}

func TestForkContextCancellationWaitsForActiveSession(t *testing.T) {
	accepted, peer := net.Pipe()
	t.Cleanup(func() { _ = accepted.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	waiting := make(chan struct{})
	ln := &oneConnListener{
		conn:    accepted,
		closed:  make(chan struct{}),
		waiting: waiting,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	opened := &Opened{}
	g := &Global{Log: logx.New()}
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- opened.forEachAccepted(ctx, ln, g, false, func(net.Conn, *Global) {
			close(started)
			<-release
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("accepted session did not start")
	}
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not wait for another connection")
	}

	cancel()
	select {
	case err := <-result:
		t.Fatalf("accept loop returned before canceled session finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("error=%v want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("accept loop did not return after canceled session finished")
	}
}

func TestForkAcceptErrorWaitsForActiveSession(t *testing.T) {
	accepted, peer := net.Pipe()
	t.Cleanup(func() { _ = accepted.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	wantErr := errors.New("accept failed")
	ln := &oneConnListener{
		conn:      accepted,
		closed:    make(chan struct{}),
		acceptErr: wantErr,
	}
	opened := &Opened{}
	g := &Global{Log: logx.New()}
	started := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- opened.forEachAccepted(context.Background(), ln, g, false, func(net.Conn, *Global) {
			close(started)
			<-release
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("accepted session did not start")
	}
	select {
	case err := <-result:
		t.Fatalf("accept loop returned before active session finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, wantErr) {
			t.Fatalf("error=%v want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("accept loop did not return after active session finished")
	}
}

func TestConnectForkContextCancellationClosesAndWaitsForActiveSession(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	opened := &Opened{
		Dial:     func(context.Context) (net.Conn, error) { return conn, nil },
		Interval: time.Hour,
	}
	g := &Global{Log: logx.New()}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	started := make(chan struct{})
	readErr := make(chan error, 1)
	result := make(chan error, 1)
	go func() {
		result <- runConnectForkLoop(ctx, opened, g, func(_ context.Context, _ *Global, c net.Conn) error {
			close(started)
			var buf [1]byte
			_, err := c.Read(buf[:])
			readErr <- err
			return err
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("connect session did not start")
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("error=%v want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("connect loop did not stop after cancellation")
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("child read succeeded after cancellation")
		}
	default:
		t.Fatal("connect loop returned before active session finished")
	}
}

type countingCloseStream struct {
	closes atomic.Int32
	err    error
}

func (*countingCloseStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (*countingCloseStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *countingCloseStream) Close() error {
	s.closes.Add(1)
	return s.err
}
func (*countingCloseStream) ShutdownWrite() error { return nil }

func TestOpenedCloseIsConcurrentAndIdempotent(t *testing.T) {
	wantErr := errors.New("close failure")
	stream := &countingCloseStream{err: wantErr}
	o := &Opened{Stream: stream}

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- o.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, wantErr) {
			t.Errorf("Close error=%v want %v", err, wantErr)
		}
	}
	if got := stream.closes.Load(); got != 1 {
		t.Fatalf("stream closed %d times, want 1", got)
	}
	if got := o.EffectiveStream(); got != stream {
		t.Fatalf("close mutated exported stream: got %T", got)
	}
}
