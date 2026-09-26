package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Timestamps are wall-clock values. Comparisons keep direction and block metadata.
var dumpHeaderMeta = regexp.MustCompile(`([<>]) .*?( length=\d+ from=\d+ to=\d+\n)`)

func normalizeDump(s string) string {
	return dumpHeaderMeta.ReplaceAllString(s, "${1}${2}")
}

func mustDump(t *testing.T, cfg Config, dir string, offset uint64, data []byte) string {
	t.Helper()
	var out bytes.Buffer
	cfg.Dump = &out
	if err := dump(cfg, dir, offset, data); err != nil {
		t.Fatal(err)
	}
	return normalizeDump(out.String())
}

func TestVerboseDumpText(t *testing.T) {
	data := []byte{'A', '\t', 'b', '\n', '\a', '\b', '\v', '\f', '\r', '\\', 0x00, 0x7f, ' '}
	got := mustDump(t, Config{Verbose: true}, ">", 0, data)
	want := "> length=13 from=0 to=12\nA\tb\n\\a\\b\\v\\f\\r\\\\.. "
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestHexDumpOneLine(t *testing.T) {
	got := mustDump(t, Config{Hex: true}, "<", 0, []byte{0x00, 'A', 0xff})
	want := "< length=3 from=0 to=2\n 00 41 ff\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestHexDumpStaysOneLine(t *testing.T) {
	data := bytes.Repeat([]byte{0x10}, 17)
	got := mustDump(t, Config{Hex: true}, ">", 0, data)
	body := bodyAfterHeader(t, got, ">", len(data))
	if strings.Count(body, "\n") != 1 || strings.Count(body, " 10") != 17 {
		t.Fatalf("body = %q", body)
	}
}

func TestCombinedDumpBreaksOnNewline(t *testing.T) {
	got := mustDump(t, Config{Verbose: true, Hex: true}, ">", 0, []byte("ab\ncd"))
	want := "> length=5 from=0 to=4\n" +
		" 61 62 0a                                         ab.\n" +
		" 63 64                                            cd\n" +
		"--\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestCombinedDumpSplitsAfterSixteenBytes(t *testing.T) {
	got := mustDump(t, Config{Verbose: true, Hex: true}, "<", 4, []byte("0123456789abcdefX"))
	want := "< length=17 from=4 to=20\n" +
		" 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66  0123456789abcdef\n" +
		" 58                                               X\n" +
		"--\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestCombinedDumpIncludesNewlineAtRowEnd(t *testing.T) {
	data := append(bytes.Repeat([]byte{'A'}, 15), '\n')
	got := mustDump(t, Config{Verbose: true, Hex: true}, ">", 0, data)
	want := "> length=16 from=0 to=15\n" +
		" 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 0a  AAAAAAAAAAAAAAA.\n" +
		"--\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestDumpOffsetsAccumulate(t *testing.T) {
	var out bytes.Buffer
	cfg := Config{Dump: &out, Verbose: true}
	if err := dump(cfg, ">", 0, []byte("ab")); err != nil {
		t.Fatal(err)
	}
	if err := dump(cfg, ">", 2, []byte("cde")); err != nil {
		t.Fatal(err)
	}
	got := normalizeDump(out.String())
	want := "> length=2 from=0 to=1\nab> length=3 from=2 to=4\ncde"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestTransferDumpOffsetsFollowReads(t *testing.T) {
	var out bytes.Buffer
	left := FDStream{
		R: &chunkReader{chunks: [][]byte{[]byte("abcd"), []byte("ef")}},
		W: io.Discard,
		C: nopCloser{},
	}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{
		LeftToRight: true,
		Verbose:     true,
		Dump:        &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := normalizeDump(out.String())
	want := "> length=4 from=0 to=3\nabcd> length=2 from=4 to=5\nef"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestDumpLengthUsesReadSize(t *testing.T) {
	var out bytes.Buffer
	wantErr := errors.New("write failed")
	left := FDStream{R: &oneShotReader{data: []byte("abcdefgh")}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: &partialWriter{n: 3, err: wantErr}, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{
		LeftToRight: true,
		Verbose:     true,
		Dump:        &out,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Transfer error = %v, want %v", err, wantErr)
	}
	got := normalizeDump(out.String())
	want := "> length=8 from=0 to=7\nabcdefgh"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestTransferPropagatesVerboseDumpErrors(t *testing.T) {
	want := errors.New("dump failed")
	left := FDStream{R: &oneShotReader{data: []byte("payload")}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{
		LeftToRight: true,
		Verbose:     true,
		Dump:        errorWriter{err: want},
	})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "verbose dump") {
		t.Fatalf("Transfer error = %v, want verbose dump of %v", err, want)
	}
}

func TestTransferRejectsShortVerboseDumpWrites(t *testing.T) {
	left := FDStream{R: &oneShotReader{data: []byte("payload")}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{
		LeftToRight: true,
		Hex:         true,
		Dump:        shortWriter{},
	})
	if !errors.Is(err, io.ErrShortWrite) || !strings.Contains(err.Error(), "verbose dump") {
		t.Fatalf("Transfer error = %v, want verbose dump short write", err)
	}
}

func TestLargeDumpMatchesSmallPathFormatting(t *testing.T) {
	pattern := []byte{'A', '\n', 0xff, 'B'}
	for _, hexMode := range []bool{false, true} {
		cfg := Config{Verbose: !hexMode, Hex: hexMode}
		small := mustDump(t, cfg, "<", 0, pattern)
		n := 1
		for dumpBodyLimit(cfg, n*len(pattern)) <= maxDumpOutputBuffer {
			n *= 2
		}
		data := bytes.Repeat(pattern, n)
		large := mustDump(t, cfg, "<", 0, data)
		smallBody := bodyAfterHeader(t, small, "<", len(pattern))
		largeBody := bodyAfterHeader(t, large, "<", len(data))
		var want string
		if hexMode {
			want = strings.Repeat(strings.TrimSuffix(smallBody, "\n"), n) + "\n"
		} else {
			want = strings.Repeat(smallBody, n)
		}
		if largeBody != want {
			t.Fatalf("hex=%v: large body differs from the small-path encoding", hexMode)
		}
	}
}

func bodyAfterHeader(t *testing.T, got, dir string, n int) string {
	t.Helper()
	header := fmt.Sprintf("%s length=%d from=0 to=%d\n", dir, n, n-1)
	body, ok := strings.CutPrefix(got, header)
	if !ok {
		t.Fatalf("header = %q, want prefix %q", got, header)
	}
	return body
}

func TestLargeCombinedDumpMatchesSmallRows(t *testing.T) {
	cfg := Config{Verbose: true, Hex: true}
	for _, pattern := range [][]byte{
		[]byte("0123456789abcdef"),
		[]byte("ab\ncd\n"),
	} {
		small := mustDump(t, cfg, ">", 0, pattern)
		n := 1
		for dumpBodyLimit(cfg, n*len(pattern)) <= maxDumpOutputBuffer {
			n *= 2
		}
		data := bytes.Repeat(pattern, n)
		large := mustDump(t, cfg, ">", 0, data)
		smallBody := bodyAfterHeader(t, small, ">", len(pattern))
		largeBody := bodyAfterHeader(t, large, ">", len(data))
		row, ok := strings.CutSuffix(smallBody, "--\n")
		if !ok {
			t.Fatalf("small body missing terminator: %q", smallBody)
		}
		if largeBody != strings.Repeat(row, n)+"--\n" {
			t.Fatalf("pattern %q: large combined body differs from the small-path rows", pattern)
		}
	}
}

func TestConcurrentDumpRecordsStaySeparate(t *testing.T) {
	left := []byte("abcdefghijklmnopqrstuvwxyz")
	right := []byte("0123456789ABCDEF")
	cfg := Config{Verbose: true, Hex: true}
	seqLeft := mustDump(t, cfg, ">", 0, left)
	seqRight := mustDump(t, cfg, "<", 0, right)
	var w yieldWriter
	cfg.Dump = &w
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errc <- dump(cfg, ">", 0, left)
	}()
	go func() {
		defer wg.Done()
		errc <- dump(cfg, "<", 0, right)
	}()
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatal(err)
		}
	}
	got := normalizeDump(string(w.buf))
	if got != seqLeft+seqRight && got != seqRight+seqLeft {
		t.Fatalf("mixed records:\n%s", got)
	}
}

func BenchmarkDumpHex8K(b *testing.B) {
	benchmarkDump(b, true)
}

func BenchmarkDumpText8K(b *testing.B) {
	benchmarkDump(b, false)
}

func benchmarkDump(b *testing.B, hexMode bool) {
	data := bytes.Repeat([]byte("abc\x00\n\xffXYZ"), 8192/9)
	cfg := Config{Dump: io.Discard, Verbose: !hexMode, Hex: hexMode}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := dump(cfg, ">", 0, data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestLargeBuffersAreNotPooled(t *testing.T) {
	if shouldPoolBuffer(maxPooledBufferSize + 1) {
		t.Fatal("oversized buffer would be retained")
	}
	if !shouldPoolBuffer(maxPooledBufferSize) {
		t.Fatal("pool boundary buffer would not be reused")
	}
}

func BenchmarkDefaultBufferPool(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		buf := getBuf(8192)
		putBuf(buf)
	}
}

type chunkReader struct {
	chunks [][]byte
	i      int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.i >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.i])
	r.i++
	return n, nil
}

type yieldWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (w *yieldWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.mu.Lock()
		w.buf = append(w.buf, b)
		w.mu.Unlock()
		runtime.Gosched()
	}
	return len(p), nil
}

type partialWriter struct {
	n   int
	err error
}

func (w *partialWriter) Write(p []byte) (int, error) {
	n := w.n
	if n > len(p) {
		n = len(p)
	}
	return n, w.err
}
