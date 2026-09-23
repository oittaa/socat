//go:build linux || darwin

package xio_test

import (
	"context"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/execopen"
)

func TestOpenEXECPtyOptionFailureUnregistersSignals(t *testing.T) {
	xio.ResetChildSignalPassForTest()
	t.Cleanup(xio.ResetChildSignalPassForTest)

	spec, err := parse.ParseSpec("EXEC:sleep 30,pty,sighup,ioctl-int=0:0")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenPreparedSpec(context.Background(), prepared, xio.ModeRDWR, xio.NewSession(xio.Options{Linger: time.Second}, logx.New()))
	if err == nil || !strings.Contains(err.Error(), "ioctl-int") {
		t.Fatalf("error=%v want ioctl-int PTY master failure after Start", err)
	}
	enabled, n, pids := xio.ChildSignalPassStateForTest(syscall.SIGHUP)
	if n != 0 {
		t.Fatalf("stale registered pids after PTY failure: n=%d pids=%v enabled=%v", n, pids, enabled)
	}
}

func TestOpenEXECFiveSIGHUPOccurrencesRejected(t *testing.T) {
	xio.ResetChildSignalPassForTest()
	t.Cleanup(xio.ResetChildSignalPassForTest)
	spec, err := parse.ParseSpec("EXEC:true,sighup,sighup,sighup,sighup,sighup")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenPreparedSpec(context.Background(), prepared, xio.ModeRDWR, xio.NewSession(xio.Options{Linger: time.Second}, logx.New()))
	if err == nil || !strings.Contains(err.Error(), "too many sub processes registered for signal 1") {
		t.Fatalf("error=%v want too many", err)
	}
}
