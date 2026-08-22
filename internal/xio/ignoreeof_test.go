package xio

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type appendReader struct {
	mu   sync.Mutex
	data []byte
}

func (r *appendReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (r *appendReader) append(data []byte) {
	r.mu.Lock()
	r.data = append(r.data, data...)
	r.mu.Unlock()
}

func TestIgnoreEOFObservesPromptAppend(t *testing.T) {
	source := &appendReader{}
	reader := NewIgnoreEOF(source)
	if reader.delay > 2*time.Millisecond || reader.maxDelay != time.Second {
		t.Fatalf("ignoreeof backoff initial=%v max=%v, want prompt start and classic 1s ceiling", reader.delay, reader.maxDelay)
	}
	result := make(chan string, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := reader.Read(buf)
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		result <- string(buf[:n])
	}()

	time.Sleep(2 * time.Millisecond)
	source.append([]byte("appended"))
	select {
	case got := <-result:
		if got != "appended" {
			t.Fatalf("Read=%q want appended", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ignoreeof did not observe append before a short relay linger would expire")
	}
}

func TestIgnoreEOFCloseInterruptsBackoff(t *testing.T) {
	reader := NewIgnoreEOF(&appendReader{})
	reader.delay = reader.maxDelay
	done := make(chan error, 1)
	go func() {
		_, err := reader.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	start := time.Now()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read error=%v want net.ErrClosed", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("Close took %s to interrupt ignoreeof backoff", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close did not interrupt ignoreeof backoff")
	}
}
