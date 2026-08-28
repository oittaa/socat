//go:build windows

package xio

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/windows"
)

type descriptorModeTestStream struct {
	r io.Reader
	w bytes.Buffer
}

func (s *descriptorModeTestStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *descriptorModeTestStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (*descriptorModeTestStream) Close() error                  { return nil }
func (*descriptorModeTestStream) ShutdownWrite() error          { return nil }

type oneByteReader struct{ r io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

func TestWindowsTextDescriptorModeRead(t *testing.T) {
	inner := &descriptorModeTestStream{r: oneByteReader{r: strings.NewReader("a\r\nb\rc\r\n")}}
	stream, err := applyDescriptorMode(mustSpec(t, "FD:3,text"), inner)
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

func TestWindowsTextDescriptorModeWrite(t *testing.T) {
	inner := &descriptorModeTestStream{r: strings.NewReader("")}
	stream, err := applyDescriptorMode(mustSpec(t, "FD:3,o-text"), inner)
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

func TestWindowsTextDescriptorModeRealFileRoundTrip(t *testing.T) {
	f, err := os.CreateTemp("", "s-w-")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	t.Cleanup(func() {
		_ = f.Close()
		_ = os.Remove(name)
	})
	if _, err := f.Write([]byte("from\r\nfile\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	spec := mustSpec(t, "FD:3,text")
	stream, err := WrapCommon(spec, FileStream(f))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from\nfile\n" {
		t.Fatalf("text file read=%q", got)
	}

	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	stream, err = WrapCommon(spec, FileStream(f))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("to\nfile\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "to\r\nfile\r\n" {
		t.Fatalf("raw text file bytes=%q", raw)
	}
	if _, ok := stream.(interface{ UnwrapZeroCopyStream() relay.Stream }); ok {
		t.Fatal("text descriptor wrapper must not expose a zero-copy bypass")
	}
}

func TestWindowsBinaryDescriptorModeIsRaw(t *testing.T) {
	inner := &descriptorModeTestStream{r: strings.NewReader("a\r\n")}
	stream, err := applyDescriptorMode(mustSpec(t, "FD:3,bin"), inner)
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
	if _, err := applyDescriptorMode(mustSpec(t, "FD:3,binary,text"), inner); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("binary,text error=%v", err)
	}
	if _, err := applyDescriptorMode(mustSpec(t, "FD:3,binary,text=0"), inner); err != nil {
		t.Fatalf("disabled text must leave binary mode valid: %v", err)
	}
}

var getHandleInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")

func handleFlags(handle windows.Handle) (uint32, error) {
	var flags uint32
	ok, _, callErr := getHandleInformation.Call(uintptr(handle), uintptr(unsafe.Pointer(&flags)))
	if ok == 0 {
		if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
			return 0, callErr
		}
		return 0, windows.ERROR_INVALID_HANDLE
	}
	return flags, nil
}

func TestWindowsNoinheritChangesActualHandleFlag(t *testing.T) {
	tests := []struct {
		raw         string
		initial     uint32
		wantInherit bool
	}{
		{raw: "FD:3,noinherit", initial: windows.HANDLE_FLAG_INHERIT, wantInherit: false},
		{raw: "FD:3,o-noinherit", initial: windows.HANDLE_FLAG_INHERIT, wantInherit: false},
		{raw: "FD:3,noinherit=0", initial: 0, wantInherit: true},
		{raw: "FD:3,noinherit=0,noinherit", initial: 0, wantInherit: false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			// A short prefix avoids Windows MAX_PATH surprises in CI temp roots.
			f, err := os.CreateTemp("", "s-w-")
			if err != nil {
				t.Fatal(err)
			}
			name := f.Name()
			t.Cleanup(func() {
				_ = f.Close()
				_ = os.Remove(name)
			})
			h := windows.Handle(f.Fd())
			if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, tc.initial); err != nil {
				t.Fatal(err)
			}
			if err := ApplyFDOptions(f, mustSpec(t, tc.raw)); err != nil {
				t.Fatal(err)
			}
			flags, err := handleFlags(h)
			if err != nil {
				t.Fatal(err)
			}
			if got := flags&windows.HANDLE_FLAG_INHERIT != 0; got != tc.wantInherit {
				t.Fatalf("HANDLE_FLAG_INHERIT=%v want %v (flags=%#x)", got, tc.wantInherit, flags)
			}
		})
	}
}
