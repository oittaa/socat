package relay

import (
	"context"
	"io"
	"os"
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
	// left: /dev/null (immediate EOF on read)
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()

	// right: pipe whose write end we keep open so Read never EOFs
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }() // keep open → no EOF on pr

	left := FDStream{R: null, W: null, C: null, CloseW: func() error { return nil }}
	rightInner := FDStream{R: pr, W: pr, C: pr, CloseW: func() error { return nil }}
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
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()

	var got []byte
	leftInner := FDStream{R: pr, W: pr, C: pr, CloseW: func() error { return nil }}
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
	if _, err := pw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()

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

type captureWriter struct{ fn func([]byte) }

func (c captureWriter) Write(p []byte) (int, error) {
	c.fn(p)
	return len(p), nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
