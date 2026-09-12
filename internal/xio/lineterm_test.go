package xio

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

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

func TestWantCRNLAliasLastWins(t *testing.T) {
	on, err := parse.ParseSpec("TCP:127.0.0.1:9,crlf")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(on, addrconfig.Facts{Type: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Transfer.LineEnding != addrconfig.LineEndingCRNL {
		t.Fatal("crlf alias should enable CRNL conversion")
	}
	crorlf, err := parse.ParseSpec("TCP:127.0.0.1:9,crorlf")
	if err != nil {
		t.Fatal(err)
	}
	config, err = addrconfig.Decode(crorlf, addrconfig.Facts{Type: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Transfer.LineEnding != addrconfig.LineEndingCROrLF {
		t.Fatal("crorlf must stay distinct from crnl")
	}
}

func TestCrorlfDisableDoesNotKeepConversion(t *testing.T) {
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,crorlf,crorlf=0")
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Transfer.LineEnding != addrconfig.LineEndingRaw {
		t.Fatalf("crorlf,crorlf=0 ending=%v", config.Transfer.LineEnding)
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
		config, err := decodeAddress(s)
		if err == nil {
			_, err = SetupStream(config, inner)
		}
		if err == nil || !strings.Contains(err.Error(), "no value permitted") {
			t.Fatalf("%s: err=%v want no value permitted", spec, err)
		}
	}
}
