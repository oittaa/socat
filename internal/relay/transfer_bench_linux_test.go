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
	src := newZeroCopyFixture(b, transferBenchBytes)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ln.Close() })

	client, probe := dialAccept(b, ln)
	plan := prepareZeroCopy(fileStream(src), NetStream{Conn: client})
	if plan == nil {
		b.Fatal("expected kernel zero-copy plan for regular file → TCP")
	}
	_ = plan.Close()
	_ = probe.Close()
	_ = client.Close()
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(transferBenchBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}
		client, server := dialAccept(b, ln)
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
		}()
		right := NetStream{Conn: client}
		b.StartTimer()
		err := Transfer(context.Background(), fileStream(src), right, Config{
			LeftToRight: true,
			BufferSize:  transferBenchBuffer,
		})
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		<-drained
		_ = right.Close()
	}
}

func newZeroCopyFixture(b *testing.B, n int) *os.File {
	b.Helper()
	f, err := os.CreateTemp(b.TempDir(), "zc-src")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write(bytesRepeat(n)); err != nil {
		b.Fatal(err)
	}
	return f
}

func fileStream(f *os.File) FDStream {
	return FDStream{R: f, W: io.Discard, C: nopCloser{}}
}

func dialAccept(b *testing.B, ln net.Listener) (client, server net.Conn) {
	b.Helper()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	server, err = ln.Accept()
	if err != nil {
		b.Fatal(err)
	}
	return client, server
}

func bytesRepeat(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = 'Z'
	}
	return p
}
