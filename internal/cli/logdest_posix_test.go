//go:build linux || darwin

package cli

import (
	"strings"
	"testing"
)

func TestParseArgsRejectsUnknownFacility(t *testing.T) {
	_, err := ParseArgs([]string{"-lynotafacility", "STDIN", "STDOUT"})
	if err == nil || !strings.Contains(err.Error(), `unknown syslog facility "notafacility"`) {
		t.Fatalf("err=%v", err)
	}
}

func TestParseArgsDumpFDUnix(t *testing.T) {
	cfg, err := ParseArgs([]string{"-D", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DumpFDs {
		t.Fatal("DumpFDs not set")
	}
}
