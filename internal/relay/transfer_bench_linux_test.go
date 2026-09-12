//go:build linux

package relay

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
)

func BenchmarkTransferZeroCopy(b *testing.B) {
	payload := bytesRepeat(transferBenchBytes)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ln.Close() })

	src, dst := openZeroCopyPair(b, ln, payload)
	probe := acceptTCP(b, ln)
	plan := prepareZeroCopy(src, dst)
	if plan == nil {
		b.Fatal("expected kernel zero-copy plan for regular file → TCP")
	}
	_ = plan.Close()
	_ = probe.Close()
	_ = src.(FDStream).R.(*os.File).Close()
	_ = dst.(NetStream).Conn.Close()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		left, right := openZeroCopyPair(b, ln, payload)
		server := acceptTCP(b, ln)
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
		}()
		b.StartTimer()
		err := Transfer(context.Background(), left, right, Config{
			LeftToRight: true,
			BufferSize:  transferBenchBuffer,
		})
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		<-drained
		_ = right.(NetStream).Conn.Close()
		_ = left.(FDStream).R.(*os.File).Close()
	}
}

func openZeroCopyPair(b *testing.B, ln net.Listener, payload []byte) (Stream, Stream) {
	b.Helper()
	f, err := os.CreateTemp(b.TempDir(), "zc-src")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		b.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		b.Fatal(err)
	}
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	return FDStream{R: f, W: io.Discard, C: nopCloser{}}, NetStream{Conn: client}
}

func acceptTCP(b *testing.B, ln net.Listener) net.Conn {
	b.Helper()
	c, err := ln.Accept()
	if err != nil {
		b.Fatal(err)
	}
	return c
}

func bytesRepeat(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = 'Z'
	}
	return p
}
