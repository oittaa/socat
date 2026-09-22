//go:build libwrapdiff

package xio

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLibwrapDifferential compares tcpwrap decisions with Debian libwrap.
// A permit from this package when libwrap denies is a failure. A deny when
// libwrap permits is recorded and is not a failure.
func TestLibwrapDifferential(t *testing.T) {
	if _, err := os.Stat("/tmp/lwchk"); err != nil {
		t.Fatal("libwrap probe /tmp/lwchk is not installed")
	}
	dir := t.TempDir()
	stats := &diffStats{}

	baseline := diffCase{
		name:  "baseline-allow-exact",
		allow: []byte("socat: 127.0.0.1\n"),
		deny:  []byte("ALL: ALL\n"),
		peer:  "127.0.0.1",
	}
	got, lw, err := compareLibwrap(dir, "baseline", baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !got || !lw {
		t.Fatalf("baseline did not permit on both sides (go %v libwrap %v); differential is not trustworthy", got, lw)
	}
	stats.agree++

	for _, c := range fixedLibwrapCases() {
		checkDiff(t, dir, stats, c)
	}
	rng := rand.New(rand.NewSource(20260922))
	for i, c := range randomLibwrapCases(rng, 800) {
		c.name = fmt.Sprintf("rand-%d", i)
		checkDiff(t, dir, stats, c)
	}
	t.Logf("differential: %d agree, %d stricter (go deny, libwrap permit), %d fail-open", stats.agree, stats.stricter, stats.failOpen)
	if stats.failOpen > 0 {
		t.Fatalf("%d cases permitted by tcpwrap and denied by libwrap", stats.failOpen)
	}
}

type diffStats struct {
	agree    int
	stricter int
	failOpen int
}

type diffCase struct {
	name      string
	allow     []byte
	deny      []byte
	peer      string
	local     string
	peerPort  int
	localPort int
	daemon    string
}

func (c diffCase) norm() diffCase {
	if c.peer == "" {
		c.peer = "127.0.0.1"
	}
	if c.local == "" {
		c.local = "127.0.0.1"
	}
	if c.peerPort == 0 {
		c.peerPort = 9999
	}
	if c.localPort == 0 {
		c.localPort = 8080
	}
	if c.daemon == "" {
		c.daemon = "socat"
	}
	if c.allow == nil {
		c.allow = []byte("\n")
	}
	if c.deny == nil {
		c.deny = []byte("\n")
	}
	return c
}

func checkDiff(t *testing.T, dir string, stats *diffStats, c diffCase) {
	t.Helper()
	goPermit, lwPermit, err := compareLibwrap(dir, c.name, c)
	if err != nil {
		t.Errorf("%s: %v", c.name, err)
		return
	}
	switch {
	case goPermit == lwPermit:
		stats.agree++
	case goPermit && !lwPermit:
		stats.failOpen++
		t.Errorf("FAIL-OPEN %s go PERMIT libwrap DENY\nallow %q\ndeny %q\npeer %s local %s:%d daemon %s",
			c.name, c.allow, c.deny, c.peer, c.local, c.norm().localPort, c.norm().daemon)
	default:
		stats.stricter++
		t.Logf("stricter %s go DENY libwrap PERMIT allow %q deny %q peer %s", c.name, c.allow, c.deny, c.peer)
	}
}

func compareLibwrap(dir, name string, c diffCase) (goPermit, lwPermit bool, err error) {
	c = c.norm()
	base := filepath.Join(dir, strings.ReplaceAll(name, "/", "_"))
	allowPath := base + ".allow"
	denyPath := base + ".deny"
	if err = os.WriteFile(allowPath, c.allow, 0o644); err != nil {
		return false, false, err
	}
	if err = os.WriteFile(denyPath, c.deny, 0o644); err != nil {
		return false, false, err
	}
	cfg := tcpwrapConfig{
		enabled:       true,
		daemon:        c.daemon,
		allow:         allowPath,
		deny:          denyPath,
		allowRequired: true,
		denyRequired:  true,
	}
	peer := &net.TCPAddr{IP: net.ParseIP(c.peer), Port: c.peerPort}
	local := &net.TCPAddr{IP: net.ParseIP(c.local), Port: c.localPort}
	goPermit = tcpwrapAllowed(cfg, peer, local) == nil

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/tmp/lwchk", allowPath, denyPath, c.daemon, c.peer,
		strconv.Itoa(c.peerPort), c.local, strconv.Itoa(c.localPort))
	out, runErr := cmd.CombinedOutput()
	permit, ok := parseLibwrapVerdict(out)
	if !ok {
		return goPermit, false, fmt.Errorf("libwrap verdict missing (%v): %s", runErr, out)
	}
	return goPermit, permit, nil
}

func parseLibwrapVerdict(out []byte) (permit bool, ok bool) {
	for _, line := range bytes.Split(out, []byte("\n")) {
		switch string(bytes.TrimSpace(line)) {
		case "PERMIT":
			permit, ok = true, true
		case "DENY":
			permit, ok = false, true
		}
	}
	return permit, ok
}

func fixedLibwrapCases() []diffCase {
	allDeny := []byte("ALL: ALL\n")
	empty := []byte("\n")
	var cases []diffCase

	add := func(name string, allow, deny []byte, peer string, extra ...func(*diffCase)) {
		c := diffCase{name: name, allow: allow, deny: deny, peer: peer}
		for _, fn := range extra {
			fn(&c)
		}
		cases = append(cases, c)
	}
	port := func(p int) func(*diffCase) { return func(c *diffCase) { c.localPort = p } }
	local := func(ip string) func(*diffCase) { return func(c *diffCase) { c.local = ip } }
	daemon := func(name string) func(*diffCase) { return func(c *diffCase) { c.daemon = name } }

	add("allow-deny-keyword", []byte("socat: 127.0.0.1: deny\n"), allDeny, "127.0.0.1")
	add("spawn-then-deny", []byte("socat: 127.0.0.1: spawn /bin/true : deny\n"), allDeny, "127.0.0.1")
	add("bad-option", []byte("socat: 127.0.0.1: nosuchopt\n"), allDeny, "127.0.0.1")
	add("aclexec-false", []byte("socat: 127.0.0.1: aclexec /bin/false\n"), allDeny, "127.0.0.1")
	add("aclexec-true", []byte("socat: 127.0.0.1: aclexec /bin/true\n"), allDeny, "127.0.0.1")
	add("option-not-last", []byte("socat: 127.0.0.1: allow : spawn /bin/true\n"), allDeny, "127.0.0.1")
	add("deny-table-allow", empty, []byte("socat: 127.0.0.1: allow\n"), "127.0.0.1")
	add("deny-allow-equals", empty, []byte("socat: 127.0.0.1: allow=\n"), "127.0.0.1")
	add("spawn-empty", []byte("socat: 127.0.0.1: spawn\n"), allDeny, "127.0.0.1")
	add("spawn-ok", []byte("socat: 127.0.0.1: spawn /bin/false\n"), allDeny, "127.0.0.1")
	add("keepalive-value", []byte("socat: 127.0.0.1: keepalive 1\n"), allDeny, "127.0.0.1")
	add("keepalive-ok", []byte("socat: 127.0.0.1: keepalive\n"), allDeny, "127.0.0.1")
	add("severity-bogus", []byte("socat: 127.0.0.1: severity bogus.level\n"), allDeny, "127.0.0.1")
	add("severity-auth-info", []byte("socat: 127.0.0.1: severity=auth.info\n"), allDeny, "127.0.0.1")
	add("severity-eq-info", []byte("socat: 127.0.0.1: severity =info\n"), allDeny, "127.0.0.1")
	add("severity-warn", []byte("socat: 127.0.0.1: severity warn\n"), allDeny, "127.0.0.1")
	add("severity-error", []byte("socat: 127.0.0.1: severity error\n"), allDeny, "127.0.0.1")
	add("severity-authpriv", []byte("socat: 127.0.0.1: severity authpriv.info\n"), allDeny, "127.0.0.1")
	add("severity-syslog", []byte("socat: 127.0.0.1: severity syslog.info\n"), allDeny, "127.0.0.1")
	add("severity-ftp", []byte("socat: 127.0.0.1: severity ftp.info\n"), allDeny, "127.0.0.1")
	add("severity-local0", []byte("socat: 127.0.0.1: severity local0.debug\n"), allDeny, "127.0.0.1")
	add("umask-999", []byte("socat: 127.0.0.1: umask 999\n"), allDeny, "127.0.0.1")
	add("umask-022", []byte("socat: 127.0.0.1: umask 022\n"), allDeny, "127.0.0.1")
	add("umask-backslash", []byte("socat: 127.0.0.1: umask 0\\22\n"), allDeny, "127.0.0.1")
	add("linger-abc", []byte("socat: 127.0.0.1: linger abc\n"), allDeny, "127.0.0.1")
	add("linger-0", []byte("socat: 127.0.0.1: linger 0\n"), allDeny, "127.0.0.1")
	add("nice-none", []byte("socat: 127.0.0.1: nice\n"), allDeny, "127.0.0.1")
	add("nice-neg", []byte("socat: 127.0.0.1: nice -5\n"), allDeny, "127.0.0.1")
	add("rfc931-empty", []byte("socat: 127.0.0.1: rfc931\n"), allDeny, "127.0.0.1")
	add("rfc931-0", []byte("socat: 127.0.0.1: rfc931 0\n"), allDeny, "127.0.0.1")
	add("rfc931-00", []byte("socat: 127.0.0.1: rfc931 00\n"), allDeny, "127.0.0.1")
	add("rfc931-1", []byte("socat: 127.0.0.1: rfc931 1\n"), allDeny, "127.0.0.1")
	add("banners", []byte("socat: 127.0.0.1: banners /tmp\n"), allDeny, "127.0.0.1")
	add("setenv-foo", []byte("socat: 127.0.0.1: setenv FOO\n"), allDeny, "127.0.0.1")
	add("setenv-empty", []byte("socat: 127.0.0.1: setenv\n"), allDeny, "127.0.0.1")
	add("user-nobody", []byte("socat: 127.0.0.1: user nobody\n"), allDeny, "127.0.0.1")
	add("user-nobody-nogroup", []byte("socat: 127.0.0.1: user nobody.nogroup\n"), allDeny, "127.0.0.1")
	add("user-bad-group", []byte("socat: 127.0.0.1: user nobody.nosuchgrp\n"), allDeny, "127.0.0.1")
	add("user-missing", []byte("socat: 127.0.0.1: user nosuchuser\n"), allDeny, "127.0.0.1")
	add("user-eq", []byte("socat: 127.0.0.1: user = nobody\n"), allDeny, "127.0.0.1")
	add("user-backslash", []byte("socat: 127.0.0.1: user HOST\\runneradmin\n"), allDeny, "127.0.0.1")
	add("group-root", []byte("socat: 127.0.0.1: group root\n"), allDeny, "127.0.0.1")
	add("group-missing", []byte("socat: 127.0.0.1: group nosuchgrp\n"), allDeny, "127.0.0.1")
	// twist is not compared: libwrap executes it and does not return.
	add("allow-empty-opt", []byte("socat: 127.0.0.1:\n"), allDeny, "127.0.0.1")
	add("allow-ws-opt", []byte("socat: 127.0.0.1:   \n"), allDeny, "127.0.0.1")
	add("escaped-colon-deny", []byte("socat: 127.0.0.1 \\: deny\n"), allDeny, "127.0.0.1")
	add("spawn-colon", []byte("socat: 127.0.0.1: spawn /bin/echo\\:hi\n"), allDeny, "127.0.0.1")
	add("bracket-split-deny", []byte("socat: 127.0.0.1: spawn echo [ : deny\n"), allDeny, "127.0.0.1")
	add("deny-allow-backslash", empty, []byte("socat: 127.0.0.1: all\\ow\n"), "127.0.0.1")
	add("deny-keyword-spaces", []byte("socat: 127.0.0.1: deny   \n"), allDeny, "127.0.0.1")
	add("missing-colon", []byte("not a rule\n"), allDeny, "127.0.0.1")
	add("netgroup", []byte("socat: @mynet\n"), allDeny, "127.0.0.1")

	add("port-plus-80", empty, []byte("+80: ALL\n"), "10.0.0.1", port(80))
	add("port-80", empty, []byte("80: ALL\n"), "10.0.0.1", port(80))
	add("port-080", empty, []byte("080: ALL\n"), "10.0.0.1", port(80))
	add("port-plus-080", empty, []byte("+080: ALL\n"), "10.0.0.1", port(80))
	add("port-70000", empty, []byte("70000: ALL\n"), "10.0.0.1", port(80))
	add("port-other", empty, []byte("+80: ALL\n"), "10.0.0.1", port(8080))
	add("port-at-host", empty, []byte("80@127.0.0.1: ALL\n"), "10.0.0.1", port(80))
	add("port-at-other-host", empty, []byte("80@10.0.0.1: ALL\n"), "10.0.0.1", port(80), local("127.0.0.1"))
	add("server-endpoint", empty, []byte("socat@127.0.0.1: ALL\n"), "10.0.0.1")
	add("server-endpoint-other", empty, []byte("socat@10.0.0.1: ALL\n"), "10.0.0.1", local("127.0.0.1"))
	add("other-daemon", empty, []byte("socat: ALL\n"), "10.0.0.1", daemon("ftp"))
	add("daemon-0", empty, []byte("0: ALL\n"), "10.0.0.1", port(0))

	add("indented-hash", []byte(" # not a comment\nsocat: 127.0.0.1\n"), allDeny, "127.0.0.1")
	add("tab-hash", []byte("\t# not a comment\nsocat: 127.0.0.1\n"), allDeny, "127.0.0.1")
	add("comment-cont", []byte("# comment \\\nsocat: ALL\n"), allDeny, "10.0.0.1")
	add("column-comment", []byte("# comment\nsocat: 127.0.0.1\n"), allDeny, "127.0.0.1")

	add("no-final-nl-allow", []byte("socat: 127.0.0.1"), allDeny, "127.0.0.1")
	add("no-final-nl-only", []byte("socat: 127.0.0.1"), empty, "127.0.0.1")
	add("cont-eof", []byte("socat: 127.0.0.1\\\n"), allDeny, "127.0.0.1")
	add("cont-eof-only", []byte("socat: 127.0.0.1\\\n"), empty, "127.0.0.1")
	add("crlf-exact", []byte("socat: 127.0.0.1\r\n"), allDeny, "127.0.0.1")
	add("backslash-crlf-then-deny", []byte("socat: 10.0.0.9\\\r\nsocat: ALL: deny\n"), allDeny, "10.0.0.9")
	add("backslash-crlf-other-peer", empty, []byte("socat: 10.0.0.9\\\r\n"), "127.0.0.1")
	add("nul-deny", empty, []byte("socat: ALL\x00 EXCEPT 127.0.0.1\n"), "10.0.0.1")

	add("len-2045", append(padHosts("socat: 127.0.0.1", 2045), '\n'), allDeny, "127.0.0.1")
	add("len-2046", append(padHosts("socat: 127.0.0.1", 2046), '\n'), allDeny, "127.0.0.1")
	add("len-2047", append(padHosts("socat: 127.0.0.1", 2047), '\n'), allDeny, "127.0.0.1")
	add("len-2047-only", append(padHosts("socat: 127.0.0.1", 2047), '\n'), empty, "127.0.0.1")
	add("len-2048", append(padHosts("socat: 127.0.0.1", 2048), '\n'), allDeny, "127.0.0.1")
	add("crlf-2045", append(padHosts("socat: 127.0.0.1", 2045), '\r', '\n'), allDeny, "127.0.0.1")
	add("crlf-2046", append(padHosts("socat: 127.0.0.1", 2046), '\r', '\n'), allDeny, "127.0.0.1")
	add("cont-short", []byte("socat: 127.0.0.\\\n1\n"), allDeny, "127.0.0.1")
	add("cont-kept-2045", continuedLine(2045, false), allDeny, "127.0.0.1")
	add("cont-kept-2046", continuedLine(2046, true), allDeny, "127.0.0.1")
	add("cont-kept-2046-only", continuedLine(2046, true), empty, "127.0.0.1")
	add("cont-crlf-2045", continuedCRLF(), allDeny, "127.0.0.1")
	add("long-cont-2410", continuedLine(2410, true), allDeny, "127.0.0.1")

	add("mask-zero-prefix", []byte("socat: 0.0.0.0/0\n"), allDeny, "10.1.1.1")
	add("mask-allones", []byte("socat: 10.0.0.0/255.255.255.255\n"), allDeny, "10.1.1.1")
	add("mask-slash-32", []byte("socat: 127.0.0.1/32\n"), allDeny, "127.0.0.1")
	add("mask-slash-32-other", []byte("socat: 127.0.0.1/32\n"), allDeny, "10.0.0.1")
	add("mask-dotted-zero", []byte("socat: 0.0.0.0/0.0.0.0\n"), allDeny, "10.1.1.1")
	add("mask-8abc", []byte("socat: 10.0.0.0/8abc\n"), allDeny, "10.1.1.1")
	add("octal-net-match", empty, []byte("socat: 010.0.0.0/255.0.0.0\n"), "8.1.1.1")
	add("octal-net-other", empty, []byte("socat: 010.0.0.0/255.0.0.0\n"), "10.1.1.1")
	add("hex-net-match", empty, []byte("socat: 0x7f.0.0.0/255.0.0.0\n"), "127.1.2.3")
	add("hex-mask", empty, []byte("socat: 127.0.0.0/0xff.0.0.0\n"), "127.9.9.9")
	add("bad-octal-mask", []byte("socat: 127.0.0.1/0xff.0xff.0xff.0xff\n"), allDeny, "127.0.0.1")
	add("exact-octal", []byte("socat: 0177.0.0.1\n"), allDeny, "127.0.0.1")
	add("exact-hex", []byte("socat: 0x7f.0.0.1\n"), allDeny, "127.0.0.1")
	add("exact-octal-deny", empty, []byte("socat: 0177.0.0.1\n"), "127.0.0.1")
	add("prefix-octal", empty, []byte("socat: 0127.\n"), "127.0.0.1")
	add("prefix-127", empty, []byte("socat: 127.\n"), "127.0.0.1")
	add("allones-net-32", []byte("socat: 255.255.255.255/32\n"), allDeny, "255.255.255.255")
	add("allones-net-only", []byte("socat: 255.255.255.255/32\n"), empty, "255.255.255.255")
	add("allones-deny", empty, []byte("socat: 255.255.255.255/32\n"), "255.255.255.255")
	add("allones-hex", []byte("socat: 0xff.0xff.0xff.0xff/32\n"), allDeny, "255.255.255.255")
	add("allones-octal", empty, []byte("socat: 0377.0377.0377.0377/32\n"), "255.255.255.255")
	add("allones-peer-zero-mask", []byte("socat: 0.0.0.0/0.0.0.0: spawn /bin/true\n"), allDeny, "255.255.255.255")
	add("zero-mask-other-peer", []byte("socat: 0.0.0.0/0.0.0.0: spawn /bin/true\n"), allDeny, "10.1.1.1")
	add("allones-peer-contained", empty, []byte("socat: 255.255.255.0/24\n"), "255.255.255.255")
	add("exact-allones-host", []byte("socat: 255.255.255.255\n"), allDeny, "255.255.255.255")
	add("host-bits", empty, []byte("socat: 10.1.2.3/8\n"), "10.9.9.9")
	add("net-match", empty, []byte("socat: 10.0.0.0/8\n"), "10.1.1.1")
	add("except-nested", []byte("socat: ALL EXCEPT 127.0.0.0/255.0.0.0 EXCEPT 127.0.0.1\n"), allDeny, "127.0.0.1")
	add("except-rest", []byte("socat: ALL EXCEPT 127.0.0.0/255.0.0.0 EXCEPT 127.0.0.1\n"), allDeny, "127.0.0.2")
	add("wildcard-star", empty, []byte("socat: 192.0.2.*\n"), "192.0.2.10")
	add("wildcard-q", empty, []byte("socat: 192.0.2.?\n"), "192.0.2.1")
	add("wildcard-q-miss", empty, []byte("socat: 192.0.2.?\n"), "192.0.2.10")
	add("localhost", []byte("socat: localhost\n"), allDeny, "127.0.0.1")
	add("local-kw", []byte("socat: LOCAL\n"), allDeny, "127.0.0.1")
	add("known-kw", []byte("socat: KNOWN\n"), allDeny, "127.0.0.1")
	add("unknown-kw", empty, []byte("socat: UNKNOWN\n"), "127.0.0.1")
	add("paranoid-kw", empty, []byte("socat: PARANOID\n"), "127.0.0.1")
	return cases
}

func padHosts(rule string, n int) []byte {
	b := bytes.Repeat([]byte(" "), n)
	copy(b, rule)
	return b
}

// continuedLine builds a logical rule of n bytes split after 1000 bytes.
// bothCont puts a continuation backslash on the second piece as well.
func continuedLine(n int, bothCont bool) []byte {
	body := padHosts("socat: 127.0.0.1", n)
	if n < 1001 {
		body = padHosts("socat: 127.0.0.1", n)
	}
	head := body[:1000]
	tail := body[1000:]
	var buf bytes.Buffer
	buf.Write(head)
	buf.WriteString("\\\n")
	buf.Write(tail)
	if bothCont {
		buf.WriteString("\\\n\n")
	} else {
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func continuedCRLF() []byte {
	head := padHosts("socat: 127.0.0.1", 2045)
	return append(head, '\\', '\n', ' ', '\r', '\n')
}

func randomLibwrapCases(rng *rand.Rand, n int) []diffCase {
	daemons := []string{"socat", "ALL", "other", "80", "+80", "080", "+080", "70000", "ALL EXCEPT socat"}
	clients := []string{
		"ALL", "127.0.0.1", "10.1.1.1", "8.1.1.1", "255.255.255.255",
		"ALL EXCEPT 127.0.0.1", "ALL EXCEPT 10.0.0.0/8 EXCEPT 10.1.1.1",
		"10.0.0.0/8", "10.1.2.3/8", "127.0.0.0/255.0.0.0", "0.0.0.0/0",
		"0.0.0.0/0.0.0.0", "127.0.0.1/32", "255.255.255.255/32",
		"255.255.255.255/255.255.255.255", "010.0.0.0/255.0.0.0",
		"0x0a.0.0.0/255.0.0.0", "0x7f.0.0.0/0xff.0.0.0", "0177.0.0.1",
		"0x7f.0.0.1", "0127.0.0.1", "127.", "10.", "0127.", "192.0.2.*",
		"10.1.1.?", "localhost",
	}
	suffixes := []string{
		"", ": allow", ": deny", ": spawn /bin/true", ": spawn", ": keepalive",
		": keepalive 1", ": severity auth.info", ": severity info", ": severity warn",
		": severity error", ": severity authpriv.info", ": severity syslog.info",
		": severity ftp.info", ": severity bogus.level", ": severity local7.notice",
		": umask 022", ": umask 0222", ": umask 999", ": umask 0\\22", ": linger 0",
		": linger abc", ": nice", ": nice -5", ": rfc931", ": rfc931 0", ": rfc931 1",
		": banners /tmp", ": setenv FOO", ": setenv", ": user nobody",
		": user nobody.nogroup", ": user nosuchuser", ": group nogroup",
		": group nosuchgrp", ": aclexec /bin/true", ": all\\ow",
		": spawn echo [ : deny", ": allow=", ": deny   ", ":", ":   ",
		" \\: deny", ": user HOST\\runneradmin", ": spawn echo\\:hi",
	}
	peers := []string{"127.0.0.1", "10.1.1.1", "8.1.1.1", "255.255.255.255", "10.0.0.9", "192.0.2.10"}
	ports := []int{80, 8080, 0}
	out := make([]diffCase, 0, n)
	for i := 0; i < n; i++ {
		daemon := daemons[rng.Intn(len(daemons))]
		client := clients[rng.Intn(len(clients))]
		suffix := suffixes[rng.Intn(len(suffixes))]
		rule := daemon + ": " + client + suffix
		nl := "\n"
		if rng.Intn(5) == 0 {
			nl = "\r\n"
		}
		body := rule + nl
		if rng.Intn(7) == 0 {
			body = "# note\n" + body
		}
		if rng.Intn(11) == 0 {
			body = "\n" + body
		}
		c := diffCase{
			peer:      peers[rng.Intn(len(peers))],
			local:     "127.0.0.1",
			localPort: ports[rng.Intn(len(ports))],
			daemon:    "socat",
		}
		if rng.Intn(2) == 0 {
			c.allow = []byte(body)
			c.deny = []byte("ALL: ALL\n")
		} else {
			c.allow = []byte("\n")
			c.deny = []byte(body)
		}
		out = append(out, c)
	}
	return out
}
