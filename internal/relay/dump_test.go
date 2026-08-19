package relay

import (
	"bytes"
	"io"
	"testing"
)

func TestDumpFormatting(t *testing.T) {
	data := []byte{'A', '\n', '\r', '\t', 0, 0x7f, 0xff}
	tests := []struct {
		name string
		hex  bool
		want string
	}{
		{name: "text", want: "> A\\n\\r\\t\\x00\\x7f\\xff\n"},
		{name: "hex", hex: true, want: "> 41 0a 0d 09 00 7f ff\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := dump(Config{Dump: &out, Hex: tc.hex}, ">", data); err != nil {
				t.Fatal(err)
			}
			if got := out.String(); got != tc.want {
				t.Fatalf("dump=%q want %q", got, tc.want)
			}
		})
	}
}

func TestLargeDumpMatchesSmallPathFormatting(t *testing.T) {
	data := bytes.Repeat([]byte{'A', '\n', 0xff}, 30_000)
	for _, hexMode := range []bool{false, true} {
		var out bytes.Buffer
		if err := dump(Config{Dump: &out, Hex: hexMode}, "<", data); err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(out.Bytes(), []byte("< ")) || !bytes.HasSuffix(out.Bytes(), []byte{'\n'}) {
			t.Fatalf("hex=%v: malformed large dump framing", hexMode)
		}
		if bytes.Count(out.Bytes(), []byte{'\n'}) != 1 {
			t.Fatalf("hex=%v: large dump was split into multiple output lines", hexMode)
		}
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
	cfg := Config{Dump: io.Discard, Hex: hexMode}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := dump(cfg, ">", data); err != nil {
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
