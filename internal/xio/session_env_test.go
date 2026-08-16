package xio

import (
	"strings"
	"testing"
	"time"
)

func TestChildEnvironOverlaysSession(t *testing.T) {
	t.Setenv("SOCAT_PEERADDR", "stale")
	g := &Global{SockAddr: "10.0.0.1", SockPort: "1", PeerAddr: "10.0.0.2", PeerPort: "2", Progname: "socat"}
	env := childEnviron(g)
	got := map[string]string{}
	for _, e := range env {
		i := strings.IndexByte(e, '=')
		if i < 0 {
			continue
		}
		got[e[:i]] = e[i+1:]
	}
	if got["SOCAT_PEERADDR"] != "10.0.0.2" {
		t.Fatalf("SOCAT_PEERADDR=%q", got["SOCAT_PEERADDR"])
	}
	if got["SOCAT_SOCKADDR"] != "10.0.0.1" {
		t.Fatalf("SOCAT_SOCKADDR=%q", got["SOCAT_SOCKADDR"])
	}
}

func TestSniffEnvFromSession(t *testing.T) {
	g := &Global{PeerAddr: "192.0.2.1", PeerPort: "9"}
	v, ok := sniffEnvValue(g, "SOCAT_PEERADDR")
	if !ok || v != "192.0.2.1" {
		t.Fatalf("got %q %v", v, ok)
	}
	path, err := expandSniffPath("/tmp/$SOCAT_PEERADDR.log", "socat", time.Now(), g)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/tmp/192.0.2.1.log" {
		t.Fatalf("path=%q", path)
	}
}

func TestForkSessionSharesStatsFlag(t *testing.T) {
	g := &Global{PeerAddr: "parent"}
	g.EnsureStatsFlag()
	a := g.forkSession()
	b := g.forkSession()
	a.PeerAddr = "child-a"
	if g.PeerAddr != "parent" || b.PeerAddr != "parent" {
		t.Fatalf("peer fields must be per-child: parent=%q b=%q", g.PeerAddr, b.PeerAddr)
	}
	a.markStatsPrinted()
	if !b.statsAlreadyPrinted() || !g.statsAlreadyPrinted() {
		t.Fatal("stats flag must be shared so --statistics prints once")
	}
}
