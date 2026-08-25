package fileopen

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openFileUse(t *testing.T, spec string, mode xio.Mode) *xio.Opened {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	var o *xio.Opened
	switch strings.ToUpper(s.Type) {
	case "TEXT":
		o, err = openTEXT(context.Background(), s, mode, nil)
	case "CREATE", "CREAT":
		o, err = openCREATE(context.Background(), s, mode, nil)
	case "OPEN", "FILE":
		o, err = openOPEN(context.Background(), s, mode, nil)
	case "GOPEN":
		o, err = openGOPEN(context.Background(), s, mode, nil)
	case "PIPE":
		o, err = openPIPE(context.Background(), s, mode, nil)
	default:
		t.Fatalf("unexpected type %s", s.Type)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func readAllFileUse(t *testing.T, r io.Reader) []byte {
	t.Helper()
	done := make(chan struct {
		b   []byte
		err error
	}, 1)
	go func() {
		b, err := io.ReadAll(r)
		done <- struct {
			b   []byte
			err error
		}{b, err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.b
	case <-time.After(3 * time.Second):
		t.Fatal("timed out reading to EOF")
		return nil
	}
}

func TestTEXTFeedsFixedString(t *testing.T) {
	o := openFileUse(t, "TEXT:hello-text", xio.ModeRead)
	if got := string(readAllFileUse(t, o.Stream)); got != "hello-text" {
		t.Fatalf("TEXT got %q", got)
	}
}

func TestCREATEThenOPENRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.bin")
	const payload = "file-bytes"
	w := openFileUse(t, "CREATE:"+path, xio.ModeWrite)
	if _, err := io.WriteString(w.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := openFileUse(t, "OPEN:"+path, xio.ModeRead)
	if got := string(readAllFileUse(t, r.Stream)); got != payload {
		t.Fatalf("OPEN got %q want %q", got, payload)
	}
}

func TestGOPENCreatesAndReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gopen.bin")
	const payload = "gopen-bytes"
	w := openFileUse(t, "GOPEN:"+path, xio.ModeWrite)
	if _, err := io.WriteString(w.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	r := openFileUse(t, "GOPEN:"+path, xio.ModeRead)
	if got := string(readAllFileUse(t, r.Stream)); got != payload {
		t.Fatalf("GOPEN got %q want %q", got, payload)
	}
}

func TestAnonymousPIPEEchoes(t *testing.T) {
	o := openFileUse(t, "PIPE", xio.ModeRDWR)
	const payload = "pipe-echo"
	if _, err := io.WriteString(o.Stream, payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(o.Stream, buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PIPE echo timed out")
	}
	if string(buf) != payload {
		t.Fatalf("PIPE got %q", buf)
	}
}
