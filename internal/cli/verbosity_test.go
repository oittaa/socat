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

func TestMalformedLogVerbosityRejected(t *testing.T) {
	cases := [][]string{
		{"-d", "-d", "-d", "-dx"},
		{"-dddx"},
		{"-d2x"},
		{"-d0x2"},
		{"-d+2"},
		{"-d-1"},
	}
	for _, args := range cases {
		_, err := ParseArgs(args)
		bad := args[len(args)-1]
		if err == nil || !strings.Contains(err.Error(), "unknown option") || !strings.Contains(err.Error(), bad) {
			t.Errorf("ParseArgs(%q) err=%v want unknown option %q", args, err, bad)
		}
	}
}

func TestEnvironmentIPAliases(t *testing.T) {
	t.Setenv("SOCAT_MAIN_WAIT", "")
	t.Setenv("SOCAT_FORK_WAIT", "")
	t.Setenv("SOCAT_TRANSFER_WAIT", "")

	cases := []struct {
		listen, resolve string
		unset           bool
		listenVer       xio.IPVersion
		resolveVer      xio.IPVersion
		warnings        int
	}{
		{"", "", false, xio.IPv4Default, xio.IPv4Default, 0},
		{"   ", "\t", false, xio.IPv4Default, xio.IPv4Default, 0},
		{"4", "0", false, xio.IPv4, xio.IPvAny, 0},
		{"6", "6", false, xio.IPv6, xio.IPv6, 0},
		{" IPv4 ", "INET6", false, xio.IPv4, xio.IPv6, 0},
		{"inet4", "ip6", false, xio.IPv4, xio.IPv6, 0},
		{"ip4", "ipv4", false, xio.IPv4, xio.IPv4, 0},
		{"0", "2", false, xio.IPv4Default, xio.IPv4Default, 2},
		{"2", "10", false, xio.IPv4Default, xio.IPv4Default, 2},
		{"10", "bogus", false, xio.IPv4Default, xio.IPv4Default, 2},
		{"6", "6", true, xio.IPv4Default, xio.IPv4Default, 0},
	}
	for _, tc := range cases {
		if tc.unset {
			t.Setenv("SOCAT_DEFAULT_LISTEN_IP", tc.listen)
			t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", tc.resolve)
			if err := os.Unsetenv("SOCAT_DEFAULT_LISTEN_IP"); err != nil {
				t.Fatal(err)
			}
			if err := os.Unsetenv("SOCAT_PREFERRED_RESOLVE_IP"); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Setenv("SOCAT_DEFAULT_LISTEN_IP", tc.listen)
			t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", tc.resolve)
		}
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

func TestEnvironmentWarningUsesConfiguredLogger(t *testing.T) {
	t.Setenv("SOCAT_MAIN_WAIT", "")
	t.Setenv("SOCAT_FORK_WAIT", "")
	t.Setenv("SOCAT_TRANSFER_WAIT", "")
	const rawListen = "  Not-An-IP  "
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", rawListen)
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "4")

	dir := t.TempDir()
	severity := regexp.MustCompile(`\[[0-9]+\] ([FEDWNI]) `)
	for _, tc := range []struct {
		name string
		args []string
		warn bool
	}{
		{"default level", []string{"-lf"}, true},
		{"errors only", []string{"-d0", "-lf"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".log")
			args := append(append([]string{}, tc.args...), path, "NOPE:bar", "STDIO")
			if code := Run(args, nil); code == 0 {
				t.Fatal("expected unknown address to fail")
			}
			text, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			levels := map[string]bool{}
			rawWarning := false
			for _, line := range strings.Split(string(text), "\n") {
				if !strings.Contains(line, "SOCAT_DEFAULT_LISTEN_IP") {
					continue
				}
				m := severity.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				levels[m[1]] = true
				if m[1] == "W" && strings.Contains(line, rawListen) {
					rawWarning = true
				}
			}
			if tc.warn {
				if !rawWarning {
					t.Fatalf("log missing warning for unrecognized listen IP:\n%s", text)
				}
				return
			}
			if len(levels) != 0 {
				t.Fatalf("-d0 still logged environment warning at %v:\n%s", levels, text)
			}
		})
	}
}
