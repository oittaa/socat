//go:build linux || darwin

package xio_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

func TestForkRoutingIgnoresDiagnosticLabel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "traffic")
	g := &xio.Global{
		Log: logx.New(), BlockSize: 8192, Linger: 10 * time.Millisecond,
		RawLeftPath: path,
	}
	lo, err := xio.OpenChannel(ctx, mustParse(t, "TCP4-LISTEN:0,bind=127.0.0.1,fork"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	lo.Label = "diagnostic label mentioning RECVFROM"
	right := mustParse(t, "PIPE")
	done := make(chan error, 1)
	go func() { done <- xio.RunOpened(ctx, lo, right, g) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("RunOpened: %v", err)
		}
	})
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", lo.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	const payload = "one transfer"
	if _, err := io.WriteString(c, payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != payload {
		t.Fatalf("echo = %q", reply)
	}
	// Receiving the echo proves both transfer directions consumed the payload.
	traffic, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(traffic) != payload {
		t.Fatalf("traffic dump = %q, want one copy of %q", traffic, payload)
	}
}
