package proxyopen

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

type writeResult struct {
	n   int
	err error
}

func testWriteConn(t *testing.T, capacity int) (*pipeConn, *reqPipeReader) {
	t.Helper()
	r, w := newReqPipe(capacity)
	c := newPipeConn(io.NopCloser(bytes.NewReader(nil)), w, nil, nil, nil)
	t.Cleanup(func() { _ = c.Close(); _ = r.Close() })
	return c, r
}

func startWrite(c *pipeConn, payload string) <-chan writeResult {
	done := make(chan writeResult, 1)
	go func() {
		n, err := c.Write([]byte(payload))
		done <- writeResult{n, err}
	}()
	return done
}

func TestPipeConnWriteRetryAfterTimeout(t *testing.T) {
	for _, retry := range []string{"old", "new"} {
		t.Run(retry, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, peer := testWriteConn(t, 3)
				if _, err := c.Write([]byte("FFF")); err != nil {
					t.Fatal(err)
				}
				done := startWrite(c, "old")
				synctest.Wait()
				_ = c.SetWriteDeadline(time.Now())
				if got := <-done; got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
					t.Fatalf("timed out Write = %+v", got)
				}
				_ = c.SetWriteDeadline(time.Time{})
				fill := make([]byte, 3)
				if _, err := io.ReadFull(peer, fill); err != nil || string(fill) != "FFF" {
					t.Fatalf("fill=%q err=%v", fill, err)
				}
				if n, err := c.Write([]byte(retry)); err != nil || n != len(retry) {
					t.Fatalf("retry = %d, %v", n, err)
				}
				_ = c.CloseWrite()
				if got, err := io.ReadAll(peer); err != nil || string(got) != retry {
					t.Fatalf("peer=%q err=%v", got, err)
				}
			})
		})
	}
}

func TestPipeConnWriteRetryAfterPartialTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := testWriteConn(t, 4)
		done := startWrite(c, "payload")
		synctest.Wait()
		_ = c.SetWriteDeadline(time.Now())
		first := <-done
		if first.n != 4 || !errors.Is(first.err, os.ErrDeadlineExceeded) {
			t.Fatalf("first Write = %+v", first)
		}
		prefix := make([]byte, first.n)
		if _, err := io.ReadFull(peer, prefix); err != nil {
			t.Fatal(err)
		}
		_ = c.SetWriteDeadline(time.Time{})
		if n, err := c.Write([]byte("payload"[first.n:])); err != nil || n != 7-first.n {
			t.Fatalf("retry = %d, %v", n, err)
		}
		_ = c.CloseWrite()
		suffix, err := io.ReadAll(peer)
		if err != nil || string(prefix)+string(suffix) != "payload" {
			t.Fatalf("peer=%q+%q err=%v", prefix, suffix, err)
		}
	})
}

func TestPipeConnConcurrentWritesTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := testWriteConn(t, 3)
		if _, err := c.Write([]byte("FFF")); err != nil {
			t.Fatal(err)
		}
		old, next := startWrite(c, "old"), startWrite(c, "new")
		synctest.Wait()
		_ = c.SetWriteDeadline(time.Now())
		for _, done := range []<-chan writeResult{old, next} {
			if got := <-done; got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
				t.Fatalf("Write = %+v", got)
			}
		}
		_ = c.CloseWrite()
		if got, err := io.ReadAll(peer); err != nil || string(got) != "FFF" {
			t.Fatalf("peer=%q err=%v", got, err)
		}
	})
}

func TestPipeConnWriteClosedReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := testWriteConn(t, 3)
		done := startWrite(c, "payload")
		synctest.Wait()
		_ = peer.Close()
		if got := <-done; got.n != 3 || !errors.Is(got.err, io.ErrClosedPipe) {
			t.Fatalf("partial Write = %+v", got)
		}
		if n, err := c.Write([]byte("x")); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("closed Write = %d, %v", n, err)
		}
	})
}

func TestPipeConnLargeWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		payload := bytes.Repeat([]byte("L"), pipeConnBuffer+8192)
		c, peer := testWriteConn(t, pipeConnBuffer)
		done := startWrite(c, string(payload))
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(peer, got); err != nil {
			t.Fatal(err)
		}
		if result := <-done; result.n != len(payload) || result.err != nil {
			t.Fatalf("Write = %+v", result)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("payload changed")
		}
	})
}

func TestPipeConnWriteDeadlineExtendThenDeliver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := testWriteConn(t, 3)
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		done := startWrite(c, "payload")
		synctest.Wait()
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		<-time.After(time.Second)
		buf := make([]byte, 7)
		if _, err := io.ReadFull(peer, buf); err != nil {
			t.Fatal(err)
		}
		if got := <-done; got.n != 7 || got.err != nil || string(buf) != "payload" {
			t.Fatalf("Write=%+v peer=%q", got, buf)
		}
	})
}

func TestPipeConnCloseWriteReturnsDeliveredCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := testWriteConn(t, 3)
		done := startWrite(c, "payload")
		synctest.Wait()
		_ = c.CloseWrite()
		got := <-done
		if got.n != 3 || !errors.Is(got.err, net.ErrClosed) {
			t.Fatalf("Write=%+v", got)
		}
		if data, err := io.ReadAll(peer); err != nil || string(data) != "pay" {
			t.Fatalf("peer=%q err=%v", data, err)
		}
	})
}
