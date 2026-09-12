//go:build linux || darwin

package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestTCPListenRejectsInvalidBacklog(t *testing.T) {
	_, err := openSpec(t, "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,backlog=0")
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if !strings.Contains(got, `backlog: invalid value "0"`) || strings.Contains(got, "backlog: backlog:") {
		t.Fatalf("error=%q want backlog: invalid value \"0\" once", got)
	}
}

func TestUDPListenAcceptsBacklogWithoutListenQueue(t *testing.T) {
	o, err := openSpec(t, "UDP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,backlog=10")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind() != xio.KindListen {
		t.Fatalf("Kind=%v want KindListen", o.Kind())
	}
}

func TestUnixListenRejectsInvalidBacklog(t *testing.T) {
	path := testutil.UnixSocketPath(t, "b-bad.sock")
	_, err := openSpec(t, "UNIX-LISTEN:"+path+",unlink-early,fork,backlog=0")
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if !strings.Contains(got, `backlog: invalid value "0"`) || strings.Contains(got, "backlog: backlog:") {
		t.Fatalf("error=%q want backlog: invalid value \"0\" once", got)
	}
}
