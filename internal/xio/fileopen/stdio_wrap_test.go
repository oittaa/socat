package fileopen

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestFDAppliesReadbytes(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	spec, err := parse.ParseSpec("FD:0,readbytes=4")
	if err != nil {
		t.Fatal(err)
	}
	fdParam, closeFD := duplicateFDForOpen(t, r)
	t.Cleanup(func() { _ = closeFD() })
	spec.Params = []string{fdParam}
	o, err := openFD(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	go func() {
		_, _ = w.Write([]byte("hello"))
		_ = w.Close()
	}()
	got, err := io.ReadAll(o.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hell" {
		t.Fatalf("got %q want hell", got)
	}
}
