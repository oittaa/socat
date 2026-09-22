package xio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func tcpwrapAllowed(cfg tcpwrapConfig, peer, local net.Addr) error {
	return tcpwrapAllowedWithResolver(context.Background(), nil, cfg, peer, local, nil)
}

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
	deny := filepath.Join(dir, "hosts.deny")
	line := "socat: 127.0.0.1 " + strings.Repeat("x", hostsAccessLineMax) + "\n"
	if err := os.WriteFile(allow, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := tcpwrapConfig{
		enabled: true, daemon: "socat",
		allow: allow, deny: deny,
		allowRequired: true, denyRequired: true,
	}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if err := tcpwrapAllowed(cfg, peer, nil); err == nil {
		t.Fatal("oversized allow line was applied")
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
		localPort  int
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
		{
			name:  "allow option deny",
			allow: "socat: 127.0.0.1: deny\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name: "deny option allow",
			deny: "socat: 127.0.0.1: allow\n",
			ip:   "127.0.0.1",
		},
		{
			name:  "unknown option denies",
			allow: "socat: 127.0.0.1: /bin/true\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "unknown option on another peer is skipped",
			allow: "socat: 10.0.0.1: /bin/true\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "aclexec denies",
			allow: "socat: 127.0.0.1: aclexec /bin/false\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "twist denies",
			allow: "socat: 127.0.0.1: twist /bin/false\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "allow option must be last",
			allow: "socat: 127.0.0.1: allow : spawn /bin/true\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "escaped colon stays inside the option",
			allow: "socat: 127.0.0.1: spawn /bin/echo\\:hi\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:      "numeric daemon matches the local port",
			deny:      "8080: ALL\n",
			ip:        "10.0.0.1",
			local:     "127.0.0.1",
			localPort: 8080, wantDeny: true,
		},
		{
			name:      "numeric daemon ignores another port",
			deny:      "8080: ALL\n",
			ip:        "10.0.0.1",
			local:     "127.0.0.1",
			localPort: 9,
		},
		{
			name:      "numeric daemon at host",
			deny:      "8080@127.0.0.1: ALL\n",
			ip:        "10.0.0.1",
			local:     "127.0.0.1",
			localPort: 8080, wantDeny: true,
		},
		{
			name:      "numeric daemon at another host",
			deny:      "8080@127.0.0.1: ALL\n",
			ip:        "10.0.0.1",
			local:     "10.0.0.1",
			localPort: 8080,
		},
		{
			name: "indented hash is not a comment",
			deny: "  # ALL: ALL\n",
			ip:   "10.0.0.1", wantDeny: true,
		},
		{
			name:  "allow line without newline is ignored",
			allow: "socat: 127.0.0.1",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name:  "earlier allow still matches before a short final line",
			allow: "socat: 127.0.0.1\nnot a finished line",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name: "deny line without newline denies another peer",
			deny: "socat: 10.0.0.1",
			ip:   "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "long allow line is ignored",
			allow: "socat: 127.0.0.1 " + strings.Repeat("x", hostsAccessLineMax) + "\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name:  "backslash CRLF is an ordinary allow line",
			allow: "socat: 127.0.0.1 \\\r\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "backslash CRLF does not swallow the next rule",
			allow: "socat: 10.0.0.9 \\\r\nsocat: ALL: deny\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name: "backslash CRLF in deny does not deny another peer",
			deny: "socat: 10.0.0.9 \\\r\n",
			ip:   "127.0.0.1",
		},
		{
			name:  "continuation at end of allow is ignored",
			allow: "socat: 127.0.0.1 \\\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name:  "crlf rule still matches",
			allow: "socat: 127.0.0.1\r\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "zero mask denies",
			allow: "socat: 0.0.0.0/0\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "all-ones mask denies",
			allow: "socat: 127.0.0.1/255.255.255.255\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "mapped literal pattern does not match a mapped peer",
			allow: "socat: [::ffff:127.0.0.1]\n",
			deny:  "ALL: ALL\n",
			ip:    "::ffff:127.0.0.1", wantDeny: true,
		},
		{
			name:  "ipv4 pattern matches a mapped peer",
			allow: "socat: 127.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "::ffff:127.0.0.1",
		},
		{
			name:  "spawn without a command denies",
			allow: "socat: 127.0.0.1: spawn\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "keepalive does not take a value",
			allow: "socat: 127.0.0.1: keepalive 1\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "keepalive with no value still allows",
			allow: "socat: 127.0.0.1: keepalive\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "severity value must be a syslog level",
			allow: "socat: 127.0.0.1: severity bogus.level\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "severity equals form is accepted",
			allow: "socat: 127.0.0.1: severity=auth.info\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "severity warn is not a libwrap level",
			allow: "socat: 127.0.0.1: severity warn\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "severity error is not a libwrap level",
			allow: "socat: 127.0.0.1: severity error\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "severity authpriv is not a libwrap facility",
			allow: "socat: 127.0.0.1: severity authpriv.info\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "rfc931 zero denies",
			allow: "socat: 127.0.0.1: rfc931 0\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "option colon inside brackets still splits",
			allow: "socat: 127.0.0.1: spawn echo [ : deny\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name: "backslash does not spell allow",
			deny: "socat: 127.0.0.1: all\\ow\n",
			ip:   "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "umask with a backslash denies",
			allow: "socat: 127.0.0.1: umask 0\\22\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "all-ones network does not match",
			allow: "socat: 255.255.255.255/32\n",
			deny:  "ALL: ALL\n",
			ip:    "255.255.255.255", wantDeny: true,
		},
		{
			name:  "all-ones peer does not match a zero mask",
			allow: "socat: 0.0.0.0/0.0.0.0\n",
			deny:  "ALL: ALL\n",
			ip:    "255.255.255.255", wantDeny: true,
		},
		{
			name:  "zero mask still matches another peer",
			allow: "socat: 0.0.0.0/0.0.0.0\n",
			deny:  "ALL: ALL\n",
			ip:    "10.1.1.1",
		},
		{
			name: "all-ones peer does not match a containing net",
			deny: "socat: 255.255.255.0/24\n",
			ip:   "255.255.255.255",
		},
		{
			name:  "exact all-ones host still matches",
			allow: "socat: 255.255.255.255\n",
			deny:  "ALL: ALL\n",
			ip:    "255.255.255.255",
		},
		{
			name:  "umask must be octal",
			allow: "socat: 127.0.0.1: umask 999\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "valid umask does not deny",
			allow: "socat: 127.0.0.1: umask 022\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "linger must be a number",
			allow: "socat: 127.0.0.1: linger abc\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "unknown user denies",
			allow: "socat: 127.0.0.1: user nosuchuser-not-real\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "unknown group denies",
			allow: "socat: 127.0.0.1: group nosuchgroup-not-real\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "empty option field denies",
			allow: "socat: 127.0.0.1:\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "whitespace option field denies",
			allow: "socat: 127.0.0.1:   \n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "escaped colon in the client field still separates options",
			allow: "socat: 127.0.0.1 \\: deny\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name: "backslash does not escape a colon in the daemon field",
			deny: "socat\\: ALL\n",
			ip:   "10.0.0.1",
		},
		{
			name: "deny file allow equals permits",
			deny: "socat: 127.0.0.1: allow=\n",
			ip:   "127.0.0.1",
		},
		{
			name:      "plus port matches the local port",
			deny:      "+80: ALL\n",
			ip:        "10.0.0.1",
			local:     "127.0.0.1",
			localPort: 80, wantDeny: true,
		},
		{
			name: "octal network matches the decimal peer",
			deny: "socat: 010.0.0.0/255.0.0.0\n",
			ip:   "8.1.1.1", wantDeny: true,
		},
		{
			name: "octal network does not match a decimal lookalike",
			deny: "socat: 010.0.0.0/255.0.0.0\n",
			ip:   "10.1.1.1",
		},
		{
			name: "exact hex host is not an inet_addr",
			deny: "socat: 0x7f.0.0.1\n",
			ip:   "127.0.0.1",
		},
		{
			name:  "exact hex host does not override deny",
			allow: "socat: 0x7f.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name:  "exact octal host does not match the decimal address",
			allow: "socat: 0177.0.0.1\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name: "hex network matches the decimal peer",
			deny: "socat: 0x7f.0.0.0/255.0.0.0\n",
			ip:   "127.1.2.3", wantDeny: true,
		},
		{
			name:  "hex mask matches inside the prefix",
			allow: "socat: 10.0.0.0/0xff.0.0.0\n",
			deny:  "ALL: ALL\n",
			ip:    "10.9.8.7",
		},
		{
			name:  "nice without a value still allows",
			allow: "socat: 127.0.0.1: nice\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "severity value may follow a spaced equals",
			allow: "socat: 127.0.0.1: severity =info\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "setenv needs a name",
			allow: "socat: 127.0.0.1: setenv\n",
			ip:    "127.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "setenv with only a name still allows",
			allow: "socat: 127.0.0.1: setenv FOO\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "prefix 32 matches the host",
			allow: "socat: 127.0.0.1/32\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "dotted zero mask matches",
			allow: "socat: 0.0.0.0/0.0.0.0\n",
			deny:  "ALL: ALL\n",
			ip:    "10.1.2.3",
		},
		{
			name: "NUL in a deny line denies another peer",
			deny: "socat: ALL\x00 EXCEPT 127.0.0.1\n",
			ip:   "10.0.0.1", wantDeny: true, wantSyntax: true,
		},
		{
			name:  "line of 2046 bytes still matches",
			allow: "socat: 127.0.0.1" + strings.Repeat(" ", hostsAccessLineMax-len("socat: 127.0.0.1")) + "\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1",
		},
		{
			name:  "line of 2047 bytes is ignored",
			allow: "socat: 127.0.0.1" + strings.Repeat(" ", hostsAccessLineMax-len("socat: 127.0.0.1")+1) + "\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name: "continued pieces of 2046 bytes are ignored",
			allow: func() string {
				content := "socat: 127.0.0.1" + strings.Repeat(" ", 2046-len("socat: 127.0.0.1"))
				return content[:1023] + "\\\n" + content[1023:] + "\\\n\n"
			}(),
			deny: "ALL: ALL\n",
			ip:   "127.0.0.1", wantDeny: true,
		},
		{
			name:  "carriage return counts toward the line limit",
			allow: "socat: 127.0.0.1" + strings.Repeat(" ", 2045-len("socat: 127.0.0.1")) + "\\\n \r\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
		},
		{
			name:  "continued line over 2046 bytes is ignored",
			allow: "socat: 127.0.0.1 \\\n" + strings.Repeat(" ", 2100) + "\n",
			deny:  "ALL: ALL\n",
			ip:    "127.0.0.1", wantDeny: true,
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
				addr := tcpPeer(t, tc.local, tc.localZone)
				if tc.localPort != 0 {
					addr.Port = tc.localPort
				}
				local = addr
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
			var syntax *hostsAccessSyntaxError
			if errors.As(err, &syntax) != tc.wantSyntax {
				t.Fatalf("syntax=%v err=%v", errors.As(err, &syntax), err)
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
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "router"), cfg, peer, nil, nil)
		if err == nil {
			t.Fatal("LOCAL permitted a dotless name")
		}
	})
	t.Run("local dotted name", func(t *testing.T) {
		cfg := writeWrapTables(t, "", "socat: LOCAL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("known", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: KNOWN\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: UNKNOWN\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, ""), cfg, peer, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("paranoid", func(t *testing.T) {
		cfg := writeWrapTables(t, "", "socat: PARANOID\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, other, "spoof.example"), cfg, peer, nil, nil)
		if err == nil {
			t.Fatal("PARANOID permitted a name that does not forward-confirm")
		}
	})
	t.Run("paranoid does not match a confirmed name", func(t *testing.T) {
		cfg := writeWrapTables(t, "", "socat: PARANOID\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("suffix", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: .example.com\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, verified, "www.example.com"), cfg, peer, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("spoofed suffix does not match", func(t *testing.T) {
		cfg := writeWrapTables(t, "socat: .example.com\n", "ALL: ALL\n")
		err := tcpwrapAllowedWithResolver(t.Context(), wrapResolver(t, other, "www.example.com"), cfg, peer, nil, nil)
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
	var syntax *hostsAccessSyntaxError
	if !errors.As(err, &syntax) {
		t.Fatal("netgroup refusal was not reported as hosts_access syntax")
	}
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Warning)
	LogRefusedPeer(lg, err)
	if buf.Len() == 0 {
		t.Fatal("syntax refusal produced no warning")
	}
	buf.Reset()
	LogRefusedPeer(lg, fmt.Errorf("refusing connection from 127.0.0.1:1 due to tcpwrapper option"))
	if buf.Len() != 0 {
		t.Fatal("ordinary refusal logged at warning")
	}
}

func TestTCPWrapIgnoredOptionLogsWarning(t *testing.T) {
	cfg := writeWrapTables(t, "socat: 127.0.0.1: spawn /bin/true\n", "ALL: ALL\n")
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Warning)
	err := tcpwrapAllowedWithResolver(context.Background(), nil, cfg, tcpPeer(t, "127.0.0.1", ""), nil, lg)
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("ignored option produced no warning")
	}
}

func TestTCPWrapAllowFramingWarnsWithoutDenying(t *testing.T) {
	cfg := writeWrapTables(t, "socat: 127.0.0.1", "")
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Warning)
	err := tcpwrapAllowedWithResolver(context.Background(), nil, cfg, tcpPeer(t, "127.0.0.1", ""), nil, lg)
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("allow framing error produced no warning")
	}
}

func TestTCPWrapDroppedReverseLookupDenies(t *testing.T) {
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.ParseIP("192.0.2.55"), "evil.example", false, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg := writeWrapTables(t, "", "socat: .evil.example\n")
	resolver := LookupResolver(resolverConfig(t, resNSAddrSpec(server.addr)))
	start := time.Now()
	err = tcpwrapAllowedWithResolver(t.Context(), resolver, cfg, tcpPeer(t, "192.0.2.55", ""), nil, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("dropped reverse lookup permitted the peer")
	}
	var lookup *hostsLookupError
	if !errors.As(err, &lookup) {
		t.Fatal("dropped reverse lookup was not a lookup failure")
	}
	var syntax *hostsAccessSyntaxError
	if errors.As(err, &syntax) {
		t.Fatal("dropped reverse lookup was reported as hosts_access syntax")
	}
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Warning)
	LogRefusedPeer(lg, err)
	if buf.Len() == 0 {
		t.Fatal("lookup failure produced no warning")
	}
	if elapsed >= 8*time.Second {
		t.Fatalf("reverse lookup stalled for %s", elapsed)
	}
}

func TestTCPWrapRejectedDNSPacketIsNotAnIdentity(t *testing.T) {
	const ip = "192.0.2.55"
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.ParseIP(ip), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.rejectThenNXDOMAIN("evil.example")
	resolver := LookupResolver(resolverConfig(t, resNSAddrSpec(server.addr)))
	cfg := writeWrapTables(t, "socat: evil.example\n", "ALL: ALL\n")
	err = tcpwrapAllowedWithResolver(t.Context(), resolver, cfg, tcpPeer(t, ip, ""), nil, nil)
	if err == nil {
		t.Fatal("rejected DNS packet permitted the peer")
	}
}

func TestTCPWrapNumericPTRIsParanoid(t *testing.T) {
	const ip = "192.0.2.55"
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.ParseIP(ip), ip, false, false)
	if err != nil {
		t.Fatal(err)
	}
	resolver := LookupResolver(resolverConfig(t, resNSAddrSpec(server.addr)))
	peer := tcpPeer(t, ip, "")
	known := writeWrapTables(t, "socat: KNOWN\n", "ALL: ALL\n")
	if err := tcpwrapAllowedWithResolver(t.Context(), resolver, known, peer, nil, nil); err == nil {
		t.Fatal("KNOWN permitted a numeric reverse name")
	}
	paranoid := writeWrapTables(t, "", "socat: PARANOID\n")
	if err := tcpwrapAllowedWithResolver(t.Context(), resolver, paranoid, peer, nil, nil); err == nil {
		t.Fatal("PARANOID permitted a numeric reverse name")
	}
}

func TestTCPWrapCNAMEPTRIsParanoid(t *testing.T) {
	const ip = "192.0.2.55"
	server, err := startFakeDNSWithAnswer(t, "127.0.0.1", net.ParseIP(ip), "alias.example", false, false)
	if err != nil {
		t.Fatal(err)
	}
	server.setCNAME("canon.example.")
	resolver := LookupResolver(resolverConfig(t, resNSAddrSpec(server.addr)))
	cfg := writeWrapTables(t, "", "socat: PARANOID\n")
	err = tcpwrapAllowedWithResolver(t.Context(), resolver, cfg, tcpPeer(t, ip, ""), nil, nil)
	if err == nil {
		t.Fatal("PARANOID permitted a CNAME reverse name")
	}
	var lookup *hostsLookupError
	if errors.As(err, &lookup) {
		t.Fatal("CNAME reverse name timed out")
	}
}

func TestTCPWrapLocalAccountOptionIsNotExecuted(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.Lookup(account.Username); err != nil {
		t.Skip("current account name is not resolvable by user.Lookup")
	}
	line := "socat: 127.0.0.1: user " + escapeHostsOption(account.Username)
	if group, gerr := user.LookupGroupId(account.Gid); gerr == nil && group.Name != "" && !strings.ContainsAny(group.Name, " \t:") {
		if _, err := user.LookupGroup(group.Name); err == nil {
			line += " : group " + escapeHostsOption(group.Name)
		}
	}
	line += "\n"
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Warning)
	cfg := writeWrapTables(t, line, "ALL: ALL\n")
	err = tcpwrapAllowedWithResolver(context.Background(), nil, cfg, tcpPeer(t, "127.0.0.1", ""), nil, lg)
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("account option produced no warning")
	}
}

func TestTCPWrapOptionBackslashKeepsWindowsAccount(t *testing.T) {
	parts, err := splitOptionField(` user HOST\runneradmin : spawn echo [ : deny`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`user HOST\runneradmin`, "spawn echo [", "deny"}
	if len(parts) != len(want) {
		t.Fatalf("parts=%q", parts)
	}
	for i := range want {
		if parts[i] != want[i] {
			t.Fatalf("parts=%q", parts)
		}
	}
}

func escapeHostsOption(s string) string {
	return strings.ReplaceAll(s, ":", `\:`)
}

func TestTCPWrapRefusalIncludesPeer(t *testing.T) {
	peer := tcpPeer(t, "127.0.0.1", "")
	err := refuseOrPass(peer, context.DeadlineExceeded)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if !strings.Contains(err.Error(), peer.String()) {
		t.Fatal("refusal omitted the peer")
	}
}
