package relay

import (
	"bytes"
	"context"
	"io"
	"testing"
)

const (
	transferBenchBytes  = 4 << 20
	transferBenchBuffer = 8192
)

func BenchmarkTransferBuffered(b *testing.B) {
	payload := bytes.Repeat([]byte("B"), transferBenchBytes)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		left := FDStream{R: bytes.NewReader(payload), W: io.Discard, C: nopCloser{}}
		right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
		if err := Transfer(context.Background(), left, right, Config{
			LeftToRight: true,
			BufferSize:  transferBenchBuffer,
		}); err != nil {
			b.Fatal(err)
		}
	}
}
