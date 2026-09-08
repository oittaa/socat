//go:build windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestWindowsHelpOmitsAcceptFD(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 1); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, addr := range []string{"ACCEPT-FD:<fdnum>", "ACCEPT:<fdnum>"} {
		if strings.Contains(help, addr) {
			t.Errorf("Windows help lists %q", addr)
		}
	}
}

func TestWindowsHelpHHHListsDescriptorModeAliases(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{"bin", "binary", "o-binary", "text", "o-text", "noinherit", "o-noinherit"} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("supported Windows descriptor option %q is missing", name)
		}
	}
}

func TestWindowsHelpOmitsTermiosSpellings(t *testing.T) {
	for _, level := range []int{2, 3} {
		var b bytes.Buffer
		if err := printHelp(&b, level); err != nil {
			t.Fatal(err)
		}
		help := b.String()
		for _, name := range []string{
			"vintr", "intr", "icanon", "ispeed", "ospeed", "sane", "echo",
			"cfmakeraw", "b115200", "tiocswinsz",
		} {
			if strings.Contains(help, "    "+name+" ") {
				t.Errorf("level %d lists unsupported termios option %q", level, name)
			}
		}
	}
}

func TestWindowsHelpOmitsDumpAndSyslogFlags(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 1); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, token := range []string{"-D", "-ly", "-lm"} {
		for _, line := range strings.Split(help, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && (fields[0] == token || strings.HasPrefix(fields[0], token+"[")) {
				t.Errorf("Windows help lists %q: %s", token, strings.TrimSpace(line))
			}
		}
	}
}
