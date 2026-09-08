package cli

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
)

func TestSignalHandlersStopWithoutSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startSignalHandlers(ctx, cancel, logx.New(), defaultSignalLogMask(), nil, make(chan os.Signal), make(chan os.Signal), nil)
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("signal handlers did not stop")
	}
}
