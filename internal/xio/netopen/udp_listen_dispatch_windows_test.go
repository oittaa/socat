//go:build windows

package netopen

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestUDPDispatchConnShortReadDropsRemainder(t *testing.T) {
	c := &udpDispatchConn{
		packets:         make(chan udpForkPacket, 4),
		done:            make(chan struct{}),
		deadlineChanged: make(chan struct{}, 1),
		pending:         udpForkPacket{data: []byte("abcd")},
		havePending:     true,
	}
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("short read n=%d err=%v data=%q", n, err, buf[:n])
	}
	if c.havePending || len(c.pending.data) != 0 || len(c.pending.oob) != 0 || c.pending.peer != nil {
		t.Fatal("dispatcher kept the unread remainder of the datagram")
	}
	if err := c.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err = c.Read(buf)
	if n != 0 {
		t.Fatalf("remainder leaked n=%d data=%q", n, buf[:n])
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, io.EOF) {
		t.Fatalf("err=%v want deadline exceeded", err)
	}
}
