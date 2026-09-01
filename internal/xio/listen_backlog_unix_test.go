//go:build linux || darwin

package xio_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixListenBacklogDefaultAndExplicit(t *testing.T) {
	pathDef := testutil.UnixSocketPath(t, "b-def.sock")
	path1 := testutil.UnixSocketPath(t, "b-1.sock")
	path20 := testutil.UnixSocketPath(t, "b-20.sock")
	openForkListen(t, "UNIX-LISTEN:"+pathDef+",unlink-early,fork")
	openForkListen(t, "UNIX-LISTEN:"+path1+",unlink-early,fork,backlog=1")
	openForkListen(t, "UNIX-LISTEN:"+path20+",unlink-early,fork,backlog=20")

	n1 := countUnixQueue(t, path1, 32, 200*time.Millisecond)
	nDef := countUnixQueue(t, pathDef, 32, 200*time.Millisecond)
	n20 := countUnixQueue(t, path20, 32, 200*time.Millisecond)
	if n1 > 4 {
		t.Fatalf("UNIX-LISTEN,backlog=1 completed %d connects, want a short queue", n1)
	}
	if nDef > 10 {
		t.Fatalf("UNIX-LISTEN default completed %d connects, want 5 not SOMAXCONN", nDef)
	}
	if n20 < 16 {
		t.Fatalf("UNIX-LISTEN,backlog=20 completed %d connects, want most of 32", n20)
	}
	if n1 >= n20 {
		t.Fatalf("backlog=1 completed %d, backlog=20 completed %d", n1, n20)
	}
}

func TestUnixListenRejectsInvalidBacklog(t *testing.T) {
	path := testutil.UnixSocketPath(t, "b-bad.sock")
	_, err := openSpec(t, "UNIX-LISTEN:"+path+",unlink-early,fork,backlog=0")
	if err == nil || !strings.Contains(err.Error(), "backlog: invalid value") {
		t.Fatalf("error=%v want backlog: invalid value", err)
	}
}

func TestAbstractListenBacklogDefaultAndExplicit(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("ABSTRACT UNIX not enabled")
	}
	nameDef := t.Name() + "-def"
	name1 := t.Name() + "-1"
	name20 := t.Name() + "-20"
	openForkListen(t, "ABSTRACT-LISTEN:"+nameDef+",fork")
	openForkListen(t, "ABSTRACT-LISTEN:"+name1+",fork,backlog=1")
	openForkListen(t, "ABSTRACT-LISTEN:"+name20+",fork,backlog=20")

	n1 := countUnixQueue(t, "@"+name1, 32, 200*time.Millisecond)
	nDef := countUnixQueue(t, "@"+nameDef, 32, 200*time.Millisecond)
	n20 := countUnixQueue(t, "@"+name20, 32, 200*time.Millisecond)
	if n1 > 4 {
		t.Fatalf("ABSTRACT-LISTEN,backlog=1 completed %d connects, want a short queue", n1)
	}
	if nDef > 10 {
		t.Fatalf("ABSTRACT-LISTEN default completed %d connects, want 5 not SOMAXCONN", nDef)
	}
	if n20 < 16 {
		t.Fatalf("ABSTRACT-LISTEN,backlog=20 completed %d connects, want most of 32", n20)
	}
}

func countUnixQueue(t *testing.T, path string, n int, timeout time.Duration) int {
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
