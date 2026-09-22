package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
)

func TestLogVerbosityFollowsManPage(t *testing.T) {
	// -d and -d2/-dd are notice; -d3/-ddd is info; -d4/-dddd is debug;
	// -d0 is errors only. Repeated flags accumulate.
	cases := []struct {
		args []string
		want logx.Level
	}{
		{nil, logx.Warning},
		{[]string{"-d"}, logx.Notice},
		{[]string{"-d1"}, logx.Notice},
		{[]string{"-dd"}, logx.Notice},
		{[]string{"-d", "-d"}, logx.Notice},
		{[]string{"-d2"}, logx.Notice},
		{[]string{"-ddd"}, logx.Info},
		{[]string{"-d", "-d", "-d"}, logx.Info},
		{[]string{"-d3"}, logx.Info},
		{[]string{"-dddd"}, logx.Debug},
		{[]string{"-d4"}, logx.Debug},
		{[]string{"-d0"}, logx.Error},
		{[]string{"-d0", "-d"}, logx.Notice},
		{[]string{"-d", "-d", "-d", "-dd"}, logx.Debug},
		{[]string{"-dd", "-d"}, logx.Info},
		{[]string{"-d2", "-dd"}, logx.Debug},
		{[]string{"-d4", "-d0"}, logx.Error},
	}
	for _, tc := range cases {
		cfg, err := ParseArgs(tc.args)
		if err != nil {
			t.Errorf("ParseArgs(%q): %v", tc.args, err)
			continue
		}
		if cfg.LogLevel != tc.want {
			t.Errorf("ParseArgs(%q) level=%v want %v", tc.args, cfg.LogLevel, tc.want)
		}
	}
}

func TestEnvironmentIPAliases(t *testing.T) {
	t.Setenv("SOCAT_MAIN_WAIT", "")
	t.Setenv("SOCAT_FORK_WAIT", "")
	t.Setenv("SOCAT_TRANSFER_WAIT", "")

	cases := []struct {
		listen, resolve string
		listenVer       xio.IPVersion
		resolveVer      xio.IPVersion
		warnings        int
	}{
		{"", "", xio.IPv4Default, xio.IPv4Default, 0},
		{"   ", "\t", xio.IPv4Default, xio.IPv4Default, 0},
		{"4", "0", xio.IPv4, xio.IPvAny, 0},
		{"6", "6", xio.IPv6, xio.IPv6, 0},
		{" IPv4 ", "INET6", xio.IPv4, xio.IPv6, 0},
		{"inet4", "ip6", xio.IPv4, xio.IPv6, 0},
		{"ip4", "ipv4", xio.IPv4, xio.IPv4, 0},
		{"0", "2", xio.IPv4Default, xio.IPv4Default, 2},
		{"2", "10", xio.IPv4Default, xio.IPv4Default, 2},
		{"10", "bogus", xio.IPv4Default, xio.IPv4Default, 2},
	}
	for _, tc := range cases {
		setIPEnv(t, "SOCAT_DEFAULT_LISTEN_IP", tc.listen)
		setIPEnv(t, "SOCAT_PREFERRED_RESOLVE_IP", tc.resolve)
		opts, _, warnings := environmentOptions()
		if opts.DefaultListenIPVersion != tc.listenVer || opts.PreferredResolveIPVersion != tc.resolveVer {
			t.Errorf("listen=%q resolve=%q got %v/%v want %v/%v",
				tc.listen, tc.resolve, opts.DefaultListenIPVersion, opts.PreferredResolveIPVersion, tc.listenVer, tc.resolveVer)
		}
		if len(warnings) != tc.warnings {
			t.Errorf("listen=%q resolve=%q warnings=%d want %d (%v)", tc.listen, tc.resolve, len(warnings), tc.warnings, warnings)
		}
	}
}

func TestEnvironmentIPUnsetIsDefault(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "6")
	unsetEnv(t, "SOCAT_DEFAULT_LISTEN_IP")
	unsetEnv(t, "SOCAT_PREFERRED_RESOLVE_IP")

	opts, _, warnings := environmentOptions()
	if len(warnings) != 0 || opts.DefaultListenIPVersion != xio.IPv4Default || opts.PreferredResolveIPVersion != xio.IPv4Default {
		t.Fatalf("unset got %v/%v warnings=%v", opts.DefaultListenIPVersion, opts.PreferredResolveIPVersion, warnings)
	}
}

func TestEnvironmentWarningUsesConfiguredLogger(t *testing.T) {
	t.Setenv("SOCAT_MAIN_WAIT", "")
	t.Setenv("SOCAT_FORK_WAIT", "")
	t.Setenv("SOCAT_TRANSFER_WAIT", "")
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "not-an-ip")
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "4")

	dir := t.TempDir()
	path := filepath.Join(dir, "socat.log")
	code := Run([]string{"-lf", path, "NOPE:bar", "STDIO"}, nil)
	if code == 0 {
		t.Fatal("expected unknown address to fail")
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !warningMentions(string(text), "SOCAT_DEFAULT_LISTEN_IP", "not-an-ip") {
		t.Fatalf("log missing warning for unrecognized listen IP:\n%s", text)
	}

	quiet := filepath.Join(dir, "quiet.log")
	code = Run([]string{"-d0", "-lf", quiet, "NOPE:bar", "STDIO"}, nil)
	if code == 0 {
		t.Fatal("expected unknown address to fail")
	}
	text, err = os.ReadFile(quiet)
	if err != nil {
		t.Fatal(err)
	}
	if levels := levelsMentioning(string(text), "SOCAT_DEFAULT_LISTEN_IP"); len(levels) != 0 {
		t.Fatalf("-d0 still logged environment warning at %v:\n%s", levels, text)
	}
}

func unsetEnv(t *testing.T, name string) {
	t.Helper()
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

func setIPEnv(t *testing.T, name, value string) {
	t.Helper()
	if value == "" {
		t.Setenv(name, "")
		return
	}
	t.Setenv(name, value)
}

func warningMentions(text, name, value string) bool {
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, name) || !strings.Contains(line, value) {
			continue
		}
		if levelsMentioning(line, name)["W"] {
			return true
		}
	}
	return false
}

var diagLevel = regexp.MustCompile(`\[[0-9]+\] ([FEDWNI]) `)

func levelsMentioning(text, needle string) map[string]bool {
	out := map[string]bool{}
	if needle == "" {
		return out
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		m := diagLevel.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out[m[1]] = true
	}
	return out
}
