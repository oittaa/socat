package relay

import (
	"context"
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
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()

	// right: pipe whose write end we keep open so Read never EOFs
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close() // keep open → no EOF on pr

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
