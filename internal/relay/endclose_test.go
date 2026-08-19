package relay

import (
	"context"
	"io"
	"net"
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
