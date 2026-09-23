//go:build linux

package execopen

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func solSocketInt(t *testing.T, fd, opt int) int {
	t.Helper()
	got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, opt)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestExecSocketpairAppliesSOPriorityToChildLinux(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:/bin/true,so-priority=5")
	if err != nil {
		t.Fatal(err)
	}
	stream, cleanup, child, err := startCmdSocketpair(mustDecodeAddress(t, spec), xio.ModeRDWR, &exec.Cmd{}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close() })
	for _, close := range cleanup {
		t.Cleanup(close)
	}
	if got := solSocketInt(t, int(asOSFile(stream).Fd()), unix.SO_PRIORITY); got != 0 {
		t.Fatalf("parent SO_PRIORITY=%d want 0", got)
	}
	if got := solSocketInt(t, int(child.Fd()), unix.SO_PRIORITY); got != 5 {
		t.Fatalf("child SO_PRIORITY=%d want 5", got)
	}
}

func TestRunExecNoForkRejectsPastSocketOptionsLinux(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:/bin/true,nofork,so-priority=5")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	err = runExecNoFork(context.Background(), nil, prepared.Config, &xio.Global{Log: logx.New()}, xio.ModeRDWR)
	if err == nil {
		t.Fatal("expected leftover PASTSOCKET error")
	}
	if !strings.Contains(err.Error(), `option "so-priority" not inquired`) {
		t.Fatalf("err=%v want option %q not inquired", err, "so-priority")
	}
}
