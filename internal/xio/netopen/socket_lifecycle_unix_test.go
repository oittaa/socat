//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketConnectRetryWaitsBetweenAttempts(t *testing.T) {
	spec := "SOCKET-CONNECT:2:0:" + ipv4SocketHex(1, [4]byte{127, 0, 0, 1}) + ",retry=1,interval=0.15"
	start := time.Now()
	prepared, err := xio.PrepareSpec(mustSocketSpec(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenPreparedSpec(context.Background(), prepared, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("connect to 127.0.0.1:1 succeeded")
	}
	if elapsed < 120*time.Millisecond {
		t.Fatalf("retry did not wait interval: elapsed %s err=%v", elapsed, err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("retry hung for %s: %v", elapsed, err)
	}
}

func TestSocketListenAcceptTimeout(t *testing.T) {
	spec := "SOCKET-LISTEN:2:0:" + ipv4SocketHex(0, [4]byte{127, 0, 0, 1}) + ",reuseaddr,accept-timeout=0.2"
	start := time.Now()
	_, err := xio.OpenSpec(context.Background(), mustSocketSpec(t, spec), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("error=%v want ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("accept-timeout elapsed %s", elapsed)
	}
}
