package fileopen

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openUse(t *testing.T, spec string, mode xio.Mode) *xio.Opened {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(context.Background(), ch, mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func TestTEXTFeedsFixedString(t *testing.T) {
	o := openUse(t, "TEXT:hello-text", xio.ModeRead)
	got, err := io.ReadAll(o.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-text" {
		t.Fatalf("TEXT got %q", got)
	}
}

func TestCREATEThenOPENRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.bin")
	const payload = "file-bytes"
	w := openUse(t, "CREATE:"+path, xio.ModeWrite)
	if _, err := io.WriteString(w.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := openUse(t, "OPEN:"+path, xio.ModeRead)
	got, err := io.ReadAll(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("OPEN got %q", got)
	}
}

func TestGOPENCreatesAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gopen.bin")
	w := openUse(t, "GOPEN:"+path, xio.ModeWrite)
	if _, err := io.WriteString(w.Stream, "ab"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	a := openUse(t, "GOPEN:"+path, xio.ModeWrite)
	if _, err := io.WriteString(a.Stream, "cd"); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcd" {
		t.Fatalf("GOPEN append got %q", got)
	}
}

func TestAnonymousPIPEEcho(t *testing.T) {
	o := openUse(t, "PIPE", xio.ModeRDWR)
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

func TestFILEAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alias.bin")
	const payload = "file-alias"
	w := openUse(t, "CREATE:"+path, xio.ModeWrite)
	if _, err := io.WriteString(w.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := openUse(t, "FILE:"+path, xio.ModeRead)
	got, err := io.ReadAll(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("FILE got %q", got)
	}
}

func TestECHOAlias(t *testing.T) {
	o := openUse(t, "ECHO", xio.ModeRDWR)
	const payload = "echo-ok"
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
		t.Fatal("ECHO timed out")
	}
	if string(buf) != payload {
		t.Fatalf("ECHO got %q", buf)
	}
}

func TestCREATAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creat.bin")
	const payload = "creat-ok"
	w := openUse(t, "CREAT:"+path, xio.ModeWrite)
	if _, err := io.WriteString(w.Stream, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("CREAT got %q", got)
	}
}

func TestOPENRepeatedFtruncateAppliesEachOccurrence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	_ = openUse(t, "OPEN:"+path+",ftruncate=8,ftruncate=3", xio.ModeWrite)
	n := 0
	for _, op := range ops {
		if op == "ftruncate" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("ftruncate count=%d want 2 (ops=%v)", n, ops)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 3 {
		t.Fatalf("size=%d want 3", st.Size())
	}
}
