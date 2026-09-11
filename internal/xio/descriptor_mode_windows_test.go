//go:build windows

package xio

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/relay"
)

type descriptorModeTestStream struct {
	r io.Reader
	w bytes.Buffer
}

func (s *descriptorModeTestStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *descriptorModeTestStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (*descriptorModeTestStream) Close() error                  { return nil }
func (*descriptorModeTestStream) ShutdownWrite() error          { return nil }
func (*descriptorModeTestStream) StreamProps() relay.Props      { return relay.NoProps() }

type oneByteReader struct{ r io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

type crThenErrorReader struct {
	err  error
	done bool
}

func (r *crThenErrorReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	p[0] = '\r'
	return 1, nil
}

func TestWindowsTextDescriptorModeRead(t *testing.T) {
	inner := &descriptorModeTestStream{r: oneByteReader{r: strings.NewReader("a\r\nb\rc\r\n")}}
	stream, err := applyDescriptorMode(mustDecodeAddress(t, mustSpec(t, "FD:3,text")), inner)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a\nb\rc\n"; string(got) != want {
		t.Fatalf("translated read=%q want %q", got, want)
	}
}

func TestWindowsTextDescriptorModePreservesCRWhenPeekFails(t *testing.T) {
	wantErr := errors.New("peek failed")
	reader := newWindowsTextReader(&crThenErrorReader{err: wantErr})
	buf := make([]byte, 8)
	n, err := reader.Read(buf)
	if n != 1 || buf[0] != '\r' {
		t.Fatalf("Read=(%d, %q), want consumed CR", n, buf[:n])
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v want %v", err, wantErr)
	}
}

func TestWindowsTextDescriptorModeWrite(t *testing.T) {
	inner := &descriptorModeTestStream{r: strings.NewReader("")}
	stream, err := applyDescriptorMode(mustDecodeAddress(t, mustSpec(t, "FD:3,o-text")), inner)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("a\nb\r\n")
	n, err := stream.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(input) {
		t.Fatalf("Write consumed %d bytes, want %d", n, len(input))
	}
	if got, want := inner.w.String(), "a\r\nb\r\r\n"; got != want {
		t.Fatalf("translated write=%q want %q", got, want)
	}
}

func TestWindowsBinaryDescriptorModeIsRaw(t *testing.T) {
	inner := &descriptorModeTestStream{r: strings.NewReader("a\r\n")}
	stream, err := applyDescriptorMode(mustDecodeAddress(t, mustSpec(t, "FD:3,bin")), inner)
	if err != nil {
		t.Fatal(err)
	}
	if stream != inner {
		t.Fatal("binary mode unexpectedly wrapped the native raw stream")
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "a\r\n" {
		t.Fatalf("binary read=%q want raw CRLF", got)
	}
}

func TestWindowsDescriptorTextModesAreMutuallyExclusive(t *testing.T) {
	inner := &descriptorModeTestStream{r: strings.NewReader("")}
	if _, err := applyDescriptorMode(mustDecodeAddress(t, mustSpec(t, "FD:3,binary,text")), inner); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("binary,text error=%v", err)
	}
	if _, err := applyDescriptorMode(mustDecodeAddress(t, mustSpec(t, "FD:3,binary,text=0")), inner); err != nil {
		t.Fatalf("disabled text must leave binary mode valid: %v", err)
	}
}
