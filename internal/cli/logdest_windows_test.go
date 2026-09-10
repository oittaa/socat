//go:build windows

package cli

import (
	"strings"
	"testing"
)

func TestParseArgsWindowsRejectsSyslogAndDump(t *testing.T) {
	for _, flag := range []string{"-ly", "-lylocal0", "-lm", "-lmlocal0", "-D"} {
		_, err := ParseArgs([]string{flag, "STDIN", "STDOUT"})
		want := "-ly"
		switch {
		case strings.HasPrefix(flag, "-lm"):
			want = "-lm"
		case flag == "-D":
			want = "-D"
		}
		if err == nil || err.Error() != `option "`+want+`" is not implemented` {
			t.Fatalf("%s: %v", flag, err)
		}
	}
}
