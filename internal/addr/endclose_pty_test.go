package addr

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestPTYEndCloseTransferExits(t *testing.T) {
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	left := fileStream(null)

	ptySpec := parse.Spec{Type: "PTY", Options: []parse.Option{{Name: "end-close"}}}
	// BoolOption needs flag style
	ptySpec.Options = []parse.Option{{Name: "end-close", Has: false}}
	o, err := openPTY(context.Background(), ptySpec, ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	right := o.Stream

	cfg := relay.Config{
		BufferSize:   8192,
		Linger:       100 * time.Millisecond,
		LeftToRight:  true,
		RightToLeft:  true,
		NoCloseLeft:  streamIsEndClose(left),
		NoCloseRight: streamIsEndClose(right),
	}
	t.Logf("NoClose L/R = %v/%v", cfg.NoCloseLeft, cfg.NoCloseRight)

	done := make(chan error, 1)
	go func() {
		done <- relay.Transfer(context.Background(), left, right, cfg)
	}()
	select {
	case err := <-done:
		t.Logf("ok err=%v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("PTY end-close transfer hung")
	}
}
