//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"sync"
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
