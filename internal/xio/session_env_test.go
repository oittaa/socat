package xio

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func environMap(env []string) map[string]string {
	got := make(map[string]string)
	for _, entry := range env {
		i := strings.IndexByte(entry, '=')
		if i >= 0 {
			got[entry[:i]] = entry[i+1:]
		}
	}
	return got
}

func TestChildEnvironOverlaysSession(t *testing.T) {
	t.Setenv("SOCAT_PEERADDR", "stale")
	g := NewSession(Options{Progname: "socat"}, nil)
	g.SockAddr = "10.0.0.1"
	g.SockPort = "1"
	g.PeerAddr = "10.0.0.2"
	g.PeerPort = "2"
	got := environMap(childEnviron(g))
	if got["SOCAT_PEERADDR"] != "10.0.0.2" {
		t.Fatalf("SOCAT_PEERADDR=%q", got["SOCAT_PEERADDR"])
	}
	if got["SOCAT_SOCKADDR"] != "10.0.0.1" {
		t.Fatalf("SOCAT_SOCKADDR=%q", got["SOCAT_SOCKADDR"])
	}
	if got["SOCAT_VERSION"] == "" {
		t.Fatal("SOCAT_VERSION is empty")
	}
	pid := strconv.Itoa(os.Getpid())
	if got["SOCAT_PID"] != pid || got["SOCAT_PPID"] != pid {
		t.Fatalf("PID=%q PPID=%q want %q", got["SOCAT_PID"], got["SOCAT_PPID"], pid)
	}
}

func TestSessionEnvironUsesPrognameAndSocatCompatibilityNames(t *testing.T) {
	g := NewSession(Options{Progname: "relay"}, nil)
	g.SessionVars = map[string]string{"TIMESTAMP": "now"}
	got := environMap(sessionEnv(g))
	for _, name := range []string{"SOCAT_TIMESTAMP", "RELAY_TIMESTAMP", "SOCAT_VERSION", "RELAY_VERSION"} {
		if got[name] == "" {
			t.Errorf("%s is empty", name)
		}
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

func TestPreferredResolveVersionFromEnvironment(t *testing.T) {
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "6")
	if got := preferredResolveVersion(&Global{}); got != IPv6 {
		t.Fatalf("env=6 got %v", got)
	}
	if got := preferredResolveVersion(NewSession(Options{IPVersion: IPv4}, nil)); got != IPv4 {
		t.Fatalf("explicit -4 must win, got %v", got)
	}
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "0")
	if got := preferredResolveVersion(&Global{}); got != IPvAny {
		t.Fatalf("env=0 got %v", got)
	}
}

func TestEnvironmentWaitDuration(t *testing.T) {
	if got := environmentWaitDuration("2"); got != 2*time.Second {
		t.Fatalf("got %s", got)
	}
	for _, value := range []string{"", "invalid", "0", "-1"} {
		if got := environmentWaitDuration(value); got != 0 {
			t.Errorf("%q got %s", value, got)
		}
	}
}
