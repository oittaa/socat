package dtls13

import (
	"bytes"
	"sync"
	"testing"
)

// oracleBuffer is a mutex-protected capture of an oracle's stdout/stderr.
type oracleBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *oracleBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *oracleBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *oracleBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

func TestOracleBufferConcurrent(t *testing.T) {
	var b oracleBuffer
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_, _ = b.Write([]byte("x"))
				_ = b.String()
				_ = b.Bytes()
			}
		}()
	}
	wg.Wait()
	if b.String() != string(bytes.Repeat([]byte("x"), 800)) {
		t.Fatalf("wrote %d bytes", len(b.String()))
	}
}
