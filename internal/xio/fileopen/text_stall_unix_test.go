//go:build linux || darwin

package fileopen

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func TestSTALLReadDeadlineStillFires(t *testing.T) {
	o, err := openSTALL(context.Background(), addrconfig.Address{Type: "STALL"}, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	f := o.Stream().(relay.FDStream).R.(*os.File)
	if err := f.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.Read(make([]byte, 1))
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%v", err)
		}
	case <-ctx.Done():
		t.Fatal("read blocked past the deadline")
	}
}
