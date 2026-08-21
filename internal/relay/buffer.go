package relay

import (
	"sync"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 8192)
		return &b
	},
}

// Avoid pinning one-off user-selected buffers as large as 256 MiB in the
// process-wide pool. Typical and moderately enlarged relay buffers still reuse
// allocations; exceptionally large buffers are released after the transfer.
const maxPooledBufferSize = 256 << 10

func getBuf(size int) *[]byte {
	bp := bufPool.Get().(*[]byte)
	if cap(*bp) < size {
		b := make([]byte, size)
		return &b
	}
	*bp = (*bp)[:size]
	return bp
}

func putBuf(bp *[]byte) {
	bufPool.Put(bp)
}

func shouldPoolBuffer(capacity int) bool {
	return capacity <= maxPooledBufferSize
}
