package xio

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func decodePeerPolicy(t *testing.T, text string) addrconfig.Network {
	t.Helper()
	spec, err := parse.ParseSpec(text)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type, Group: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	return config.Network
}

func TestTCPWrapExplicitMissingTableFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.allow")
	cfg := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,hosts-allow="+missing), Options{})
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err == nil {
		t.Fatal("explicit missing table unexpectedly permitted the peer")
	}
}

func TestTCPWrapOversizedExplicitTableFailsClosed(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "hosts.allow")
	if err := os.WriteFile(allow, []byte("socat: "+string(make([]byte, 70<<10))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := tcpwrapConfig{enabled: true, daemon: "socat", allow: allow, allowRequired: true}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err == nil {
		t.Fatal("unreadable explicit table unexpectedly permitted the peer")
	}
}

func TestTCPWrapMissingDefaultTablesRemainOptional(t *testing.T) {
	dir := t.TempDir()
	cfg := tcpwrapConfig{
		enabled: true,
		daemon:  "socat",
		allow:   filepath.Join(dir, "hosts.allow"),
		deny:    filepath.Join(dir, "hosts.deny"),
	}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err != nil {
		t.Fatalf("missing optional system tables should default permit: %v", err)
	}
}

func TestTCPWrapLiteralOneIsDaemonName(t *testing.T) {
	one := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,tcpwrap=1"), Options{Progname: "from-argv"})
	if !one.enabled || !one.daemonExplicit || one.daemon != "1" {
		t.Fatalf("tcpwrap=1: %+v", one)
	}
	bare := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,tcpwrap"), Options{Progname: "from-argv"})
	if !bare.enabled || bare.daemonExplicit || bare.daemon != "from-argv" {
		t.Fatalf("bare tcpwrap: %+v", bare)
	}
}

func TestTCPWrapDaemonNameSelectsHostsTable(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "hosts.allow")
	deny := filepath.Join(dir, "hosts.deny")
	if err := os.WriteFile(allow, []byte("MyDaemon: 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tables := ",hosts-allow=" + allow + ",hosts-deny=" + deny

	named := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,tcpwrap=MyDaemon"+tables), Options{})
	if named.daemon != "MyDaemon" {
		t.Fatalf("daemon=%q", named.daemon)
	}
	if err := tcpwrapAllowed(named, peer, nil); err != nil {
		t.Fatalf("tcpwrap=MyDaemon: %v", err)
	}

	bare := parseTCPWrap(decodePeerPolicy(t, "TCP4-LISTEN:1234,tcpwrap"+tables), Options{})
	if bare.daemon != "socat" {
		t.Fatalf("default daemon=%q", bare.daemon)
	}
	if err := tcpwrapAllowed(bare, peer, nil); err == nil {
		t.Fatal("default daemon unexpectedly matched MyDaemon allow rule")
	}
}

func writeWrapTables(t *testing.T, allow, deny string) tcpwrapConfig {
	t.Helper()
	dir := t.TempDir()
	allowPath := filepath.Join(dir, "hosts.allow")
	denyPath := filepath.Join(dir, "hosts.deny")
	if err := os.WriteFile(allowPath, []byte(allow), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyPath, []byte(deny), 0o644); err != nil {
		t.Fatal(err)
	}
	return tcpwrapConfig{
		enabled:       true,
		daemon:        "socat",
		allow:         allowPath,
		deny:          denyPath,
		allowRequired: true,
		denyRequired:  true,
	}
}

func tcpPeer(t *testing.T, ip, zone string) *net.TCPAddr {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("bad ip %q", ip)
	}
	return &net.TCPAddr{IP: parsed, Port: 9999, Zone: zone}
}

func TestTCPWrapHostsAccessPatterns(t *testing.T) {
	cases := []struct {
		name       string
		allow      string
		deny       string
		ip         string
		zone       string
		local      string
		localZone  string
		daemon     string
		wantDeny   bool
		wantSyntax bool
	}{
		{
			name:  "except allow excludes listed peer",
			allow: "socat: ALL EXCEPT 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name:  "except allow permits other peers",
			allow: "socat: ALL EXCEPT 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "10.0.0.1",
		},
		{
			name: "trailing-dot prefix denies",
			deny: "socat: 127.\n",
			ip:   "127.0.0.1", wantDeny: true,
		},
		{
			name: "trailing-dot prefix permits other nets",
			deny: "socat: 127.\n",
			ip:   "10.0.0.1",
		},
		{
			name: "ipv4 net/mask denies",
			deny: "socat: 127.0.0.0/255.0.0.0\n",
			ip:   "127.1.2.3", wantDeny: true,
		},
		{
			name: "ipv4 prefix length denies",
			deny: "socat: 10.0.0.0/8\n",
			ip:   "10.1.2.3", wantDeny: true,
		},
		{
			name: "ipv4 pattern host bits do not match",
			deny: "socat: 10.1.2.3/8\n",
			ip:   "10.9.9.9",
		},
		{
			name: "ipv6 prefix denies",
			deny: "socat: [2001:db8::]/32\n",
			ip:   "2001:db8::5", wantDeny: true,
		},
		{
			name: "ipv6 prefix ignores host bits in the pattern",
			deny: "socat: [2001:db8::1]/32\n",
			ip:   "2001:db8::5", wantDeny: true,
		},
		{
			name: "ipv6 prefix permits other nets",
			deny: "socat: [2001:db8::]/32\n",
			ip:   "2001:db9::1",
		},
		{
			name: "netgroup denies",
			deny: "socat: @mynet\n",
			ip:   "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "file pattern denies",
			allow: "socat: /etc/hosts.trust\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "user at host denies when the host matches",
			allow: "socat: ALL@127.0.0.1\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "user at host skips a different peer",
			allow: "socat: nobody@10.0.0.1\n",
			ip:    "127.0.0.1",
		},
		{
			name: "wildcard star denies",
			deny: "socat: 192.0.2.*\n",
			ip:   "192.0.2.10", wantDeny: true,
		},
		{
			name: "wildcard question denies one octet digit",
			deny: "socat: 192.0.2.?\n",
			ip:   "192.0.2.1", wantDeny: true,
		},
		{
			name: "wildcard question permits two digits",
			deny: "socat: 192.0.2.?\n",
			ip:   "192.0.2.10",
		},
		{
			name: "wildcard combined with a leading dot denies",
			deny: "socat: .*.example.com\n",
			ip:   "10.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name: "daemon except permits this daemon",
			deny: "ALL EXCEPT socat: ALL\n",
			ip:   "10.0.0.1",
		},
		{
			name:   "daemon except denies other daemons",
			deny:   "ALL EXCEPT socat: ALL\n",
			ip:     "10.0.0.1",
			daemon: "ftp", wantDeny: true,
		},
		{
			name:  "server endpoint denies the matching local address",
			deny:  "socat@127.0.0.1: ALL\n",
			ip:    "10.0.0.1",
			local: "127.0.0.1", wantDeny: true,
		},
		{
			name:  "server endpoint permits another local address",
			deny:  "socat@127.0.0.1: ALL\n",
			ip:    "10.0.0.1",
			local: "10.0.0.1",
		},
		{
			name:  "nested except reinstates the inner host",
			allow: "socat: ALL EXCEPT 127.0.0.0/255.0.0.0 EXCEPT 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "nested except still denies the rest of the net",
			allow: "socat: ALL EXCEPT 127.0.0.0/255.0.0.0 EXCEPT 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.2", wantDeny: true,
		},
		{
			name:  "nested except permits outside the net",
			allow: "socat: ALL EXCEPT 127.0.0.0/255.0.0.0 EXCEPT 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "10.0.0.1",
		},
		{
			name: "other daemon netgroup is not evaluated",
			deny: "httpd: @mynet\n",
			ip:   "127.0.0.1",
		},
		{
			name: "continued except permits the excluded peer",
			deny: "socat: ALL EXCEPT \\\n10.0.0.1\n",
			ip:   "10.0.0.1",
		},
		{
			name: "continued except denies other peers",
			deny: "socat: ALL EXCEPT \\\n10.0.0.1\n",
			ip:   "127.0.0.1", wantDeny: true,
		},
		{
			name:  "shell command does not change an allow match",
			allow: "socat: 127.0.0.1: spawn /bin/false\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "missing colon denies",
			allow: "not a rule\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "comment and exact address allow",
			allow: "# comment\n\n socat: 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "earlier allow skips a later broken line",
			allow: "socat: 127.0.0.1\nthis is garbage\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "broken line denies when it is reached",
			allow: "socat: 10.0.0.1\nthis is garbage\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "bracketed ipv6 allow",
			allow: "socat: [::1]\n",
			deny:  "ALL: ALL\n",
			ip:    "::1",
		},
		{
			name: "rbl pattern denies",
			deny: "socat: {RBL}.example\n",
			ip:   "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name: "prefix length past 32 denies",
			deny: "socat: 10.0.0.0/99\n",
			ip:   "10.1.2.3", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "daemon name is case insensitive",
			allow: "SOCAT: 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "allow match is not overridden by a later bad deny",
			allow: "socat: 127.0.0.1\n",
			deny:  "socat: @mynet\n",
			ip:    "127.0.0.1",
		},
		{
			name: "scoped ipv6 exact address denies",
			deny: "socat: [fe80::1%eth0]\n",
			ip:   "fe80::1", zone: "eth0", wantDeny: true,
		},
		{
			name: "scoped ipv6 exact address permits another zone",
			deny: "socat: [fe80::1%eth0]\n",
			ip:   "fe80::1", zone: "eth1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeWrapTables(t, tc.allow, tc.deny)
			if tc.daemon != "" {
				cfg.daemon = tc.daemon
			}
			var local net.Addr
			if tc.local != "" {
				local = tcpPeer(t, tc.local, tc.localZone)
			}
			err := tcpwrapAllowed(cfg, tcpPeer(t, tc.ip, tc.zone), local)
			if !tc.wantDeny {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("permitted")
			}
			syntax := strings.Contains(err.Error(), "unsupported hosts_access")
			if syntax != tc.wantSyntax {
				t.Fatalf("syntax=%v err=%v", syntax, err)
			}
		})
	}
}

func wrapResolver(t *testing.T, answer net.IP, ptrName string) *net.Resolver {
	t.Helper()
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", answer, ptrName, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return LookupResolver(resolverConfig(t, resNSAddrSpec(server.addr)))
}

func TestTCPWrapNamePatterns(t *testing.T) {
	const ip = "192.0.2.55"
	peer := tcpPeer(t, ip, "")
	verified := net.ParseIP(ip)
	other := net.ParseIP("192.0.2.99")

	t.Run("local", func(t *testing.T) {
		cfg := writeWrapTables(t, "", "socat: LOCAL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "router"), cfg, peer, nil)
		if err == nil {
			t.Fatal("LOCAL permitted a dotless name")
		}
	})
	t.Run("local dotted name", func(t *testing.T) {
		cfg := writeWrapTables(t, "", "socat: LOCAL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("known", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: KNOWN\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: UNKNOWN\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, ""), cfg, peer, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("paranoid", func(t *testing.T) {
		cfg := writeWrapTables(t, "", "socat: PARANOID\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, other, "spoof.example"), cfg, peer, nil)
		if err == nil {
			t.Fatal("PARANOID permitted a name that does not forward-confirm")
		}
	})
	t.Run("paranoid does not match a confirmed name", func(t *testing.T) {
		cfg := writeWrapTables(t, "", "socat: PARANOID\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("suffix", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: .example.com\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("spoofed suffix does not match", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: .example.com\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, other, "www.example.com"), cfg, peer, nil)
		if err == nil {
			t.Fatal("unconfirmed reverse name matched .example.com")
		}
	})
}

func TestTCPWrapSyntaxRefusalLogsAtWarning(t *testing.T) {
	cfg := writeWrapTables(t, "", "socat: @mynet\n")
	err := tcpwrapAllowed(cfg, tcpPeer(t, "127.0.0.1", ""), nil)
	if err == nil {
		t.Fatal("netgroup permitted the peer")
	}
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Warning)
	LogRefusedPeer(lg, err)
	if !strings.Contains(buf.String(), `unsupported hosts_access syntax "@mynet"`) {
		t.Fatalf("warning log %q", buf.String())
	}
	buf.Reset()
	LogRefusedPeer(lg, fmt.Errorf("refusing connection from 127.0.0.1:1 due to tcpwrapper option"))
	if buf.Len() != 0 {
		t.Fatalf("ordinary refusal logged at warning: %q", buf.String())
	}
}
