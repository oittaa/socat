package dtls13

import "sync/atomic"

type memoryBudget struct {
	used  atomic.Int64
	limit int64
}

func (b *memoryBudget) reserve(size int) bool {
	if b == nil {
		return true
	}
	for {
		used := b.used.Load()
		if int64(size) > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+int64(size)) {
			return true
		}
	}
}

func (b *memoryBudget) release(size int) {
	if b != nil {
		b.used.Add(-int64(size))
	}
}
