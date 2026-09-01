//go:build linux || darwin

package xio_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestListenBacklogParser(t *testing.T) {
	for _, tc := range []struct {
		spec    string
		want    int
		wantErr string
	}{
		{spec: "TCP-LISTEN:1", want: 5},
		{spec: "TCP-LISTEN:1,backlog=1", want: 1},
		{spec: "TCP-LISTEN:1,backlog=20", want: 20},
		{spec: "TCP-LISTEN:1,backlog=0x10", want: 16},
		{spec: "TCP-LISTEN:1,backlog=010", want: 8},
		{spec: "TCP-LISTEN:1,backlog=0", wantErr: "invalid value"},
		{spec: "TCP-LISTEN:1,backlog=-1", wantErr: "invalid value"},
		{spec: "TCP-LISTEN:1,backlog=no", wantErr: "invalid value"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			got, err := xio.ListenBacklog(s)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error=%v want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ListenBacklog=%d want %d", got, tc.want)
			}
		})
	}
}

func TestStreamListenBacklogDefaultAndExplicit(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		spec func(backlog string) string
	}{
		{name: "tcp", spec: func(b string) string {
			return "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork" + backlogOpt(b)
		}},
		{name: "tls", spec: func(b string) string {
			return "TLS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + backlogOpt(b)
		}},
		{name: "openssl", spec: func(b string) string {
			return "OPENSSL-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + backlogOpt(b)
		}},
		{name: "ws", spec: func(b string) string {
			return "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork" + backlogOpt(b)
		}},
		{name: "wss", spec: func(b string) string {
			return "WSS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=" + cert + backlogOpt(b)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def := openForkListen(t, tc.spec(""))
			one := openForkListen(t, tc.spec("1"))
			twenty := openForkListen(t, tc.spec("20"))
			n1 := countTCPQueue(t, one.Listener.Addr().String(), 16, 200*time.Millisecond)
			nDef := countTCPQueue(t, def.Listener.Addr().String(), 16, 200*time.Millisecond)
			n20 := countTCPQueue(t, twenty.Listener.Addr().String(), 16, 200*time.Millisecond)
			if n1 > 4 {
				t.Fatalf("backlog=1 completed %d connects, want a short queue", n1)
			}
			if nDef > 10 {
				t.Fatalf("default backlog completed %d connects, want 5 not OS maximum", nDef)
			}
			if n20 < 12 {
				t.Fatalf("backlog=20 completed %d connects, want most of 16", n20)
			}
			if n1 >= n20 {
				t.Fatalf("backlog=1 completed %d, backlog=20 completed %d", n1, n20)
			}
		})
	}
}

func TestTCPListenRejectsInvalidBacklog(t *testing.T) {
	_, err := openSpec(t, "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,backlog=0")
	if err == nil || !strings.Contains(err.Error(), "backlog: invalid value") {
		t.Fatalf("error=%v want backlog: invalid value", err)
	}
}

func TestUDPListenAcceptsBacklogWithoutListenQueue(t *testing.T) {
	o, err := openSpec(t, "UDP-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,backlog=10")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindListen {
		t.Fatalf("Kind=%v want KindListen", o.Kind)
	}
}

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

func countTCPQueue(t *testing.T, addr string, n int, timeout time.Duration) int {
	t.Helper()
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	d := net.Dialer{Timeout: timeout}
	for range n {
		c, err := d.Dial("tcp", addr)
		if err != nil {
			return len(conns)
		}
		conns = append(conns, c)
	}
	return len(conns)
}
