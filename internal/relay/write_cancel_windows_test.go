//go:build windows

package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A peer that accepts but never reads can fill the TCP send buffer. The
// net.Pipe write below reaches the same blocked-Write state deterministically.
func TestTransferEndCloseCancelsBlockedWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	left := FDStream{
		R: bytes.NewReader([]byte("blocked")),
		W: io.Discard,
		C: nopCloser{},
	}
	right := testEndClose{Stream: NetStream{Conn: c1}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Transfer(ctx, left, right, Config{
			LeftToRight:  true,
			NoCloseRight: true,
		})
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked end-close write ignored cancellation")
	}
}
