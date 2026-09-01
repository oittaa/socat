//go:build windows

package xio_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestWindowsUnixListenBacklogDefaultAndExplicit(t *testing.T) {
	pathDef := testutil.UnixSocketPath(t, "b-def.sock")
	path1 := testutil.UnixSocketPath(t, "b-1.sock")
	path20 := testutil.UnixSocketPath(t, "b-20.sock")
	openWindowsUnixForkListen(t, pathDef, "")
	openWindowsUnixForkListen(t, path1, "1")
	openWindowsUnixForkListen(t, path20, "20")

	n1 := countWindowsUnixQueue(t, path1, 32, 200*time.Millisecond)
	nDef := countWindowsUnixQueue(t, pathDef, 32, 200*time.Millisecond)
	n20 := countWindowsUnixQueue(t, path20, 32, 200*time.Millisecond)
	if n1 > 8 {
		t.Fatalf("UNIX-LISTEN,backlog=1 completed %d connects, want a short queue", n1)
	}
	if nDef > 12 {
		t.Fatalf("UNIX-LISTEN default completed %d connects, want 5 not OS maximum", nDef)
	}
	if n1 >= n20 {
		t.Fatalf("backlog=1 completed %d, backlog=20 completed %d", n1, n20)
	}
}

func TestWindowsUnixListenRejectsInvalidBacklog(t *testing.T) {
	path := testutil.UnixSocketPath(t, "b-bad.sock")
	_, err := xio.OpenSpec(context.Background(), windowsUnixListenSpec(path, "0"), xio.ModeRDWR, testGlobal())
	if err == nil || !strings.Contains(err.Error(), "backlog: invalid value") {
		t.Fatalf("error=%v want backlog: invalid value", err)
	}
}

func openWindowsUnixForkListen(t *testing.T, path, backlog string) *xio.Opened {
	t.Helper()
	o, err := xio.OpenSpec(context.Background(), windowsUnixListenSpec(path, backlog), xio.ModeRDWR, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindListen || o.Listener == nil {
		t.Fatalf("Kind=%v listener=%v want KindListen", o.Kind, o.Listener)
	}
	return o
}

func windowsUnixListenSpec(path, backlog string) parse.Spec {
	opts := []parse.Option{
		{Name: "unlink-early"},
		{Name: "fork"},
	}
	if backlog != "" {
		opts = append(opts, parse.Option{Name: "backlog", Value: backlog, Has: true})
	}
	return parse.Spec{Type: "UNIX-LISTEN", Params: []string{path}, Options: opts}
}

func countWindowsUnixQueue(t *testing.T, path string, n int, timeout time.Duration) int {
	t.Helper()
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	d := net.Dialer{Timeout: timeout}
	for range n {
		c, err := d.Dial("unix", path)
		if err != nil {
			return len(conns)
		}
		conns = append(conns, c)
	}
	return len(conns)
}
