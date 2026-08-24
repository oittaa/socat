package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// endClose mimics addr.endCloseStream
type testEndClose struct{ Stream }

func (e testEndClose) ShutdownWrite() error { return nil }
func (e testEndClose) Close() error         { return nil }
func (e testEndClose) IsEndClose() bool     { return true }
func (e testEndClose) UnwrapStream() Stream { return e.Stream }

// Hang repro: left EOFs immediately; right never EOFs; end-close suppresses Close.
// Transfer must still exit after Linger.
func TestTransferEndCloseExitsAfterLinger(t *testing.T) {
	// left: immediate EOF on read
	// right: stream whose write end we keep open so Read never EOFs
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }() // keep open → no EOF on c1

	left := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}, CloseW: func() error { return nil }}
	rightInner := NetStream{Conn: c1}
	right := testEndClose{Stream: rightInner}

	ctx := context.Background()
	cfg := Config{
		BufferSize:   8192,
		Linger:       100 * time.Millisecond,
		LeftToRight:  true,
		RightToLeft:  true,
		NoCloseLeft:  false,
		NoCloseRight: true, // end-close on right
	}

	done := make(chan error, 1)
	go func() {
		done <- Transfer(ctx, left, right, cfg)
	}()

	select {
	case err := <-done:
		t.Logf("transfer returned err=%v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("transfer hung past linger+margin (end-close did not unblock)")
	}
}

// sessionWrap must Read after poll reports ready (Revents on the slice, not a copy).
func TestTransferEndCloseCopiesData(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()

	var got []byte
	leftInner := NetStream{Conn: c1}
	left := testEndClose{Stream: leftInner}
	right := FDStream{
		R:      eofReader{},
		W:      captureWriter{fn: func(p []byte) { got = append(got, p...) }},
		C:      nopCloser{},
		CloseW: func() error { return nil },
	}

	done := make(chan error, 1)
	go func() {
		done <- Transfer(context.Background(), left, right, Config{
			BufferSize:  8192,
			Linger:      100 * time.Millisecond,
			LeftToRight: true,
			RightToLeft: false,
			NoCloseLeft: true,
		})
	}()
	if _, err := c2.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transfer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transfer hung (sessionWrap did not read)")
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want hello", got)
	}
}

func TestTransferEndCloseReusesSharedStream(t *testing.T) {
	shared, collector := net.Pipe()
	defer func() { _ = shared.Close() }()
	defer func() { _ = collector.Close() }()

	left := NetStream{Conn: shared}
	for _, message := range []string{"first", "second"} {
		right := FDStream{
			R:      &oneShotReader{data: []byte(message)},
			W:      io.Discard,
			C:      nopCloser{},
			CloseW: func() error { return nil },
		}
		done := make(chan error, 1)
		go func() {
			done <- Transfer(context.Background(), left, right, Config{
				RightToLeft: true,
				NoCloseLeft: true,
			})
		}()

		buf := make([]byte, len(message))
		if _, err := io.ReadFull(collector, buf); err != nil {
			t.Fatalf("read %q: %v", message, err)
		}
		if string(buf) != message {
			t.Fatalf("got %q, want %q", buf, message)
		}
		if err := <-done; err != nil {
			t.Fatalf("transfer %q: %v", message, err)
		}
	}
}

func TestSessionWrapCloseDoesNotWaitForRead(t *testing.T) {
	started := make(chan struct{})
	block := make(chan struct{})
	inner := &recordingDeadlineStream{
		read: func([]byte) (int, error) {
			close(started)
			<-block
			return 0, io.EOF
		},
	}
	w := newSessionWrap(inner)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = w.Read(make([]byte, 1))
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Read did not enter the inner stream")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-readDone:
		t.Fatal("Close waited for the inner Read to finish")
	default:
	}
	close(block)
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("Read did not return after inner unblocked")
	}
}

func TestSessionWrapNextSessionClearsLeftoverPoke(t *testing.T) {
	inner := &recordingDeadlineStream{}
	if err := newSessionWrap(inner).Close(); err != nil {
		t.Fatal(err)
	}
	inner.mu.Lock()
	if inner.readDeadline.IsZero() {
		inner.mu.Unlock()
		t.Fatal("Close should poke a read deadline")
	}
	inner.mu.Unlock()

	_ = newSessionWrap(inner)
	inner.mu.Lock()
	gotRead, gotWrite := inner.readDeadline, inner.writeDeadline
	inner.mu.Unlock()
	if !gotRead.IsZero() || !gotWrite.IsZero() {
		t.Fatalf("next wrap left poke deadlines read=%v write=%v", gotRead, gotWrite)
	}
}

func TestSessionWrapReusesPipeAfterClosePoke(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if err := newSessionWrap(RWCStream{ReadWriteCloser: r}).Close(); err != nil {
		t.Fatal(err)
	}
	sess := newSessionWrap(RWCStream{ReadWriteCloser: r})
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		n, err := sess.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if string(buf[:n]) != "hello" {
			errCh <- fmt.Errorf("got %q", buf[:n])
			return
		}
		errCh <- nil
	}()
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("second session read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second session did not read")
	}
}

func TestTransferSerializesShutdownAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	right := &blockingLifecycleStream{
		shutdownStarted: make(chan struct{}),
		releaseShutdown: make(chan struct{}),
		closeStarted:    make(chan struct{}),
		releaseClose:    make(chan struct{}),
	}
	left := FDStream{
		R:      eofReader{},
		W:      io.Discard,
		C:      nopCloser{},
		CloseW: func() error { return nil },
	}

	done := make(chan error, 1)
	go func() {
		done <- Transfer(ctx, left, right, Config{LeftToRight: true})
	}()

	select {
	case <-right.shutdownStarted:
	case <-time.After(time.Second):
		t.Fatal("ShutdownWrite was not called")
	}
	cancel()
	select {
	case <-right.closeStarted:
		t.Fatal("Close overlapped ShutdownWrite")
	case <-time.After(20 * time.Millisecond):
	}

	close(right.releaseShutdown)
	select {
	case <-right.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Close was not called after ShutdownWrite completed")
	}
	select {
	case <-done:
		t.Fatal("Transfer returned before the cancellation close completed")
	case <-time.After(20 * time.Millisecond):
	}

	close(right.releaseClose)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transfer: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Transfer did not return after Close completed")
	}
}

func TestTransferLingerBeatsIdleTimeout(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	got := make(chan []byte, 1)
	left := FDStream{
		R:      eofReader{},
		W:      captureWriter{fn: func(p []byte) { got <- append([]byte(nil), p...) }},
		C:      nopCloser{},
		CloseW: func() error { return nil },
	}
	done := make(chan error, 1)
	go func() {
		done <- Transfer(context.Background(), left, NetStream{Conn: c1}, Config{
			Linger:      400 * time.Millisecond,
			IdleTimeout: 80 * time.Millisecond,
			LeftToRight: true,
			RightToLeft: true,
		})
	}()
	time.Sleep(150 * time.Millisecond)
	if _, err := c2.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
	select {
	case b := <-got:
		if string(b) != "late" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(time.Second):
		t.Fatal("late data was not copied during linger")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("transfer did not finish")
	}
}

type blockingLifecycleStream struct {
	shutdownStarted chan struct{}
	releaseShutdown chan struct{}
	closeStarted    chan struct{}
	releaseClose    chan struct{}
}

func (*blockingLifecycleStream) Read([]byte) (int, error) { return 0, io.EOF }
func (*blockingLifecycleStream) Write(p []byte) (int, error) {
	return len(p), nil
}
func (s *blockingLifecycleStream) ShutdownWrite() error {
	close(s.shutdownStarted)
	<-s.releaseShutdown
	return nil
}
func (s *blockingLifecycleStream) Close() error {
	close(s.closeStarted)
	<-s.releaseClose
	return nil
}

type captureWriter struct{ fn func([]byte) }

func (c captureWriter) Write(p []byte) (int, error) {
	c.fn(p)
	return len(p), nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

type recordingDeadlineStream struct {
	mu            sync.Mutex
	read          func([]byte) (int, error)
	readDeadline  time.Time
	writeDeadline time.Time
}

func (s *recordingDeadlineStream) Read(p []byte) (int, error) {
	if s.read != nil {
		return s.read(p)
	}
	return 0, io.EOF
}

func (*recordingDeadlineStream) Write(p []byte) (int, error) { return len(p), nil }
func (*recordingDeadlineStream) Close() error                { return nil }
func (*recordingDeadlineStream) ShutdownWrite() error        { return nil }

func (s *recordingDeadlineStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

func (s *recordingDeadlineStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	return nil
}

type oneShotReader struct {
	data []byte
}

func (r *oneShotReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
