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
	g.Peer.SockAddr = "10.0.0.1"
	g.Peer.SockPort = "1"
	g.Peer.PeerAddr = "10.0.0.2"
	g.Peer.PeerPort = "2"
	got := environMap(ChildEnviron(g))
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
	g.Peer.SessionVars = map[string]string{"TIMESTAMP": "now"}
	got := environMap(sessionEnv(g))
	for _, name := range []string{"SOCAT_TIMESTAMP", "RELAY_TIMESTAMP", "SOCAT_VERSION", "RELAY_VERSION"} {
		if got[name] == "" {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestChildEnvironDropsStaleTLSNames(t *testing.T) {
	t.Setenv("SOCAT_TLS_CIPHER", "stale")
	t.Setenv("RELAY_TLS_CIPHER", "stale")
	t.Setenv("RELAY_OPENSSL_CIPHER", "stale")
	g := NewSession(Options{Progname: "relay"}, nil)
	g.Peer.TLSVars = map[string]string{"CIPHER": "A"}
	got := environMap(ChildEnviron(g))
	if got["SOCAT_TLS_CIPHER"] != "A" || got["RELAY_TLS_CIPHER"] != "A" || got["RELAY_OPENSSL_CIPHER"] != "A" {
		t.Fatalf("tls env cipher SOCAT=%q RELAY=%q OPENSSL=%q", got["SOCAT_TLS_CIPHER"], got["RELAY_TLS_CIPHER"], got["RELAY_OPENSSL_CIPHER"])
	}
}

func TestChildEnvironKeepsTLSEnvWithoutSessionTLS(t *testing.T) {
	t.Setenv("SOCAT_TLS_CIPHER", "keep")
	g := NewSession(Options{}, nil)
	if got := environMap(ChildEnviron(g))["SOCAT_TLS_CIPHER"]; got != "keep" {
		t.Fatalf("SOCAT_TLS_CIPHER=%q", got)
	}
}

func TestChildEnvironDropsTLSEnvForEmptyTLSMap(t *testing.T) {
	t.Setenv("SOCAT_TLS_CIPHER", "drop")
	g := NewSession(Options{}, nil)
	g.Peer.TLSVars = map[string]string{}
	if _, ok := environMap(ChildEnviron(g))["SOCAT_TLS_CIPHER"]; ok {
		t.Fatal("empty TLS map must drop inherited SOCAT_TLS_*")
	}
}

func TestSniffEnvFromSession(t *testing.T) {
	g := &Global{Peer: peer{PeerAddr: "192.0.2.1", PeerPort: "9"}}
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

func TestRelaySessionConfigFromOptions(t *testing.T) {
	cfg := relaySessionConfig(Options{BlockSize: 4, LeftToRight: true, Linger: time.Second}, true, false)
	if cfg.BufferSize != 4 || !cfg.LeftToRight || cfg.RightToLeft || !cfg.NoCloseLeft || cfg.NoCloseRight {
		t.Fatalf("%+v", cfg)
	}
	if cfg.RawLeft != nil || cfg.OnStats != nil || cfg.OnEOF != nil {
		t.Fatal("relay session config must not attach session files or callbacks")
	}
}

func TestChannelModesUsesOptions(t *testing.T) {
	l, r := channelModes(Options{})
	if l != ModeRDWR || r != ModeRDWR {
		t.Fatalf("default %v %v", l, r)
	}
	l, r = channelModes(Options{LeftToRight: true})
	if l != ModeRead || r != ModeWrite {
		t.Fatalf("-u %v %v", l, r)
	}
	l, r = channelModes(Options{RightToLeft: true})
	if l != ModeWrite || r != ModeRead {
		t.Fatalf("-U %v %v", l, r)
	}
}
