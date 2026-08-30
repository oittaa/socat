package xio

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestSelectedLineTermOrder(t *testing.T) {
	tests := []struct {
		spec string
		want lineTermMode
	}{
		{spec: "TCP:127.0.0.1:9", want: lineTermRaw},
		{spec: "TCP:127.0.0.1:9,cr", want: lineTermCR},
		{spec: "TCP:127.0.0.1:9,crnl", want: lineTermCRNL},
		{spec: "TCP:127.0.0.1:9,crlf", want: lineTermCRNL},
		{spec: "TCP:127.0.0.1:9,crorlf", want: lineTermCRorLF},
		{spec: "TCP:127.0.0.1:9,cr,crnl", want: lineTermCRNL},
		{spec: "TCP:127.0.0.1:9,crnl,cr", want: lineTermCR},
		{spec: "TCP:127.0.0.1:9,crlf,cr", want: lineTermCR},
		{spec: "TCP:127.0.0.1:9,cr,crlf", want: lineTermCRNL},
		{spec: "TCP:127.0.0.1:9,cr,crorlf", want: lineTermCRorLF},
		{spec: "TCP:127.0.0.1:9,crorlf,cr", want: lineTermCR},
		{spec: "TCP:127.0.0.1:9,crnl,crorlf", want: lineTermCRorLF},
		{spec: "TCP:127.0.0.1:9,crorlf,crnl", want: lineTermCRNL},
		{spec: "TCP:127.0.0.1:9,crorlf=0", want: lineTermRaw},
		{spec: "TCP:127.0.0.1:9,cr,crorlf=0", want: lineTermCR},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := selectedLineTerm(s); got != tc.want {
				t.Fatalf("mode=%d want %d", got, tc.want)
			}
		})
	}
}

func TestCRWriteConvertsNLToCR(t *testing.T) {
	var buf bytes.Buffer
	inner := relay.FDStream{R: bytes.NewReader(nil), W: &buf, C: NopCloser{}, CloseW: func() error { return nil }}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,cr", inner)
	n, err := stream.Write([]byte("helo\nworld\n"))
	if err != nil || n != len("helo\nworld\n") {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if got := buf.String(); got != "helo\rworld\r" {
		t.Fatalf("wrote %q want CR endings", got)
	}
}

func TestCRReadConvertsCRToNL(t *testing.T) {
	inner := relay.FDStream{
		R:      bytes.NewReader([]byte("helo\rworld\r")),
		W:      io.Discard,
		C:      NopCloser{},
		CloseW: func() error { return nil },
	}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,cr", inner)
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "helo\nworld\n" {
		t.Fatalf("read %q want NL endings", got)
	}
}

func TestCRPartialReadWrite(t *testing.T) {
	pr, pw := io.Pipe()
	inner := relay.FDStream{R: pr, W: pw, C: pw, CloseW: func() error { return pw.Close() }}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,cr", inner)

	written := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte("ab\ncd"))
		written <- err
	}()
	buf := make([]byte, 2)
	if n, err := io.ReadFull(pr, buf); err != nil || n != 2 || string(buf) != "ab" {
		t.Fatalf("first chunk n=%d err=%v data=%q", n, err, buf)
	}
	if n, err := io.ReadFull(pr, buf[:1]); err != nil || n != 1 || buf[0] != '\r' {
		t.Fatalf("CR byte n=%d err=%v b=%q", n, err, buf[:1])
	}
	if n, err := io.ReadFull(pr, buf); err != nil || string(buf) != "cd" {
		t.Fatalf("tail n=%d err=%v data=%q", n, err, buf)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}

	readDone := make(chan string, 1)
	go func() {
		b := make([]byte, 8)
		n, err := stream.Read(b)
		if err != nil {
			readDone <- "err:" + err.Error()
			return
		}
		readDone <- string(b[:n])
	}()
	if _, err := pw.Write([]byte("xy\rz")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-readDone:
		if got != "xy\nz" {
			t.Fatalf("partial read %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading converted CR")
	}
}

func TestCRNLLoneCRStrippedCRORLFKeepsNL(t *testing.T) {
	readAll := func(opt, input string) string {
		inner := relay.FDStream{
			R:      strings.NewReader(input),
			W:      io.Discard,
			C:      NopCloser{},
			CloseW: func() error { return nil },
		}
		stream := wrapSpec(t, "TCP:127.0.0.1:9,"+opt, inner)
		got, err := io.ReadAll(stream)
		if err != nil {
			t.Fatal(err)
		}
		return string(got)
	}
	if got := readAll("crnl", "a\rb\r\nc"); got != "ab\nc" {
		t.Fatalf("crnl read %q", got)
	}
	if got := readAll("crorlf", "a\rb\r\nc"); got != "a\nb\nc" {
		t.Fatalf("crorlf read %q (must not fold into crnl)", got)
	}
	if got := readAll("cr", "a\rb\r\nc"); got != "a\nb\n\nc" {
		t.Fatalf("cr read %q", got)
	}
}

func TestCRORLFCollapsesCRLFAcrossReads(t *testing.T) {
	pr, pw := io.Pipe()
	inner := relay.FDStream{R: pr, W: io.Discard, C: pr, CloseW: func() error { return nil }}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,crorlf", inner)
	got := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		b := make([]byte, 8)
		for buf.Len() < 3 {
			n, err := stream.Read(b)
			if n > 0 {
				buf.Write(b[:n])
			}
			if err != nil {
				break
			}
		}
		got <- buf.String()
	}()
	if _, err := pw.Write([]byte("a\r")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := pw.Write([]byte("\nb")); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	select {
	case s := <-got:
		if s != "a\nb" {
			t.Fatalf("crorlf split CRLF %q want a\\nb", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func TestLineTermLastWinsWrite(t *testing.T) {
	write := func(opt, in string) string {
		var buf bytes.Buffer
		inner := relay.FDStream{R: bytes.NewReader(nil), W: &buf, C: NopCloser{}, CloseW: func() error { return nil }}
		stream := wrapSpec(t, "TCP:127.0.0.1:9,"+opt, inner)
		if _, err := stream.Write([]byte(in)); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if got := write("cr,crnl", "x\n"); got != "x\r\n" {
		t.Fatalf("cr,crnl write %q", got)
	}
	if got := write("crnl,cr", "x\n"); got != "x\r" {
		t.Fatalf("crnl,cr write %q", got)
	}
	if got := write("crorlf,cr", "x\n"); got != "x\r" {
		t.Fatalf("crorlf,cr write %q", got)
	}
	if got := write("cr,crorlf", "x\n"); got != "x\r\n" {
		t.Fatalf("cr,crorlf write %q", got)
	}
}

func TestLineTermPreservesDeadlineUnwrap(t *testing.T) {
	for _, opt := range []string{"cr", "crnl", "crorlf"} {
		t.Run(opt, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			parsed, err := parse.ParseSpec("TCP:127.0.0.1:9,rcvtimeo=0.02,sndtimeo=0.02," + opt)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := WrapCommon(parsed, timeoutPipeStream(client))
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			if found, err := relay.SetStreamReadDeadline(stream, deadline); err != nil || !found {
				t.Fatalf("SetStreamReadDeadline found=%v err=%v", found, err)
			}
			if found, err := relay.SetStreamWriteDeadline(stream, deadline); err != nil || !found {
				t.Fatalf("SetStreamWriteDeadline found=%v err=%v", found, err)
			}
		})
	}
}

func TestCrWriterPartialMatchesLength(t *testing.T) {
	w := &oneByteThenErr{err: io.ErrShortWrite}
	c := &crWriter{w: w}
	n, err := c.Write([]byte("\nX"))
	if n != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := w.buf.String(); got != "\r" {
		t.Fatalf("got %q", got)
	}
}

func TestLineTermConvertersReuseScratchBuffers(t *testing.T) {
	input := []byte("one\r\ntwo\n")
	out := make([]byte, len(input))

	crw := &crWriter{w: io.Discard}
	_, _ = crw.Write(input)
	if got := testing.AllocsPerRun(1000, func() { _, _ = crw.Write(input) }); got != 0 {
		t.Fatalf("cr writer allocations = %v, want 0 after warmup", got)
	}

	cnw := &crnlWriter{w: io.Discard}
	_, _ = cnw.Write(input)
	if got := testing.AllocsPerRun(1000, func() { _, _ = cnw.Write(input) }); got != 0 {
		t.Fatalf("crnl writer allocations = %v, want 0 after warmup", got)
	}

	var source bytes.Reader
	cnr := &crnlReader{r: &source}
	source.Reset(input)
	_, _ = cnr.Read(out)
	if got := testing.AllocsPerRun(1000, func() {
		source.Reset(input)
		_, _ = cnr.Read(out)
	}); got != 0 {
		t.Fatalf("crnl reader allocations = %v, want 0 after warmup", got)
	}

	cor := &crorlfReader{r: &source}
	source.Reset(input)
	_, _ = cor.Read(out)
	if got := testing.AllocsPerRun(1000, func() {
		source.Reset(input)
		cor.sawCR = false
		_, _ = cor.Read(out)
	}); got != 0 {
		t.Fatalf("crorlf reader allocations = %v, want 0 after warmup", got)
	}
}

func TestWantCRNLAliasLastWins(t *testing.T) {
	on, err := parse.ParseSpec("TCP:127.0.0.1:9,crlf")
	if err != nil {
		t.Fatal(err)
	}
	if !wantCRNL(on) {
		t.Fatal("crlf alias should enable CRNL conversion")
	}
	crorlf, err := parse.ParseSpec("TCP:127.0.0.1:9,crorlf")
	if err != nil {
		t.Fatal(err)
	}
	if wantCRNL(crorlf) {
		t.Fatal("crorlf must stay distinct from crnl")
	}
}

func TestClassicCRRejectsAssignment(t *testing.T) {
	inner := relay.FDStream{R: bytes.NewReader(nil), W: io.Discard, C: NopCloser{}, CloseW: func() error { return nil }}
	for _, spec := range []string{
		"TCP:127.0.0.1:9,cr=0",
		"TCP:127.0.0.1:9,crnl=false",
		"TCP:127.0.0.1:9,crlf=1",
	} {
		s, err := parse.ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := WrapCommon(s, inner); err == nil || !strings.Contains(err.Error(), "no value permitted") {
			t.Fatalf("%s: err=%v want no value permitted", spec, err)
		}
	}
}
