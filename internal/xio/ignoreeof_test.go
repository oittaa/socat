package xio

import (
	"io"
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
	if reader.delay > 2*time.Millisecond || reader.maxDelay > 10*time.Millisecond {
		t.Fatalf("ignoreeof backoff is too slow for short relay linger: initial=%v max=%v", reader.delay, reader.maxDelay)
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
