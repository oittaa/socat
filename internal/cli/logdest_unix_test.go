//go:build linux || darwin

package cli

import (
	"strings"
	"testing"
)

func TestParseArgsLoggingDestinationLastWins(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantDest LogDest
		wantFile string
		wantFac  string
	}{
		{name: "default", args: []string{"STDIN", "STDOUT"}, wantDest: LogDestStderr},
		{name: "ls", args: []string{"-ls", "STDIN", "STDOUT"}, wantDest: LogDestStderr},
		{name: "lf", args: []string{"-lf", "socat.log", "STDIN", "STDOUT"}, wantDest: LogDestFile, wantFile: "socat.log"},
		{name: "lf-then-ls", args: []string{"-lf", "socat.log", "-ls", "STDIN", "STDOUT"}, wantDest: LogDestStderr},
		{name: "ls-then-lf", args: []string{"-ls", "-lf", "socat.log", "STDIN", "STDOUT"}, wantDest: LogDestFile, wantFile: "socat.log"},
		{name: "ly", args: []string{"-ly", "STDIN", "STDOUT"}, wantDest: LogDestSyslog, wantFac: "daemon"},
		{name: "ly-local0", args: []string{"-lylocal0", "STDIN", "STDOUT"}, wantDest: LogDestSyslog, wantFac: "local0"},
		{name: "lm", args: []string{"-lm", "STDIN", "STDOUT"}, wantDest: LogDestMixed, wantFac: "daemon"},
		{name: "lm-local1", args: []string{"-lmlocal1", "STDIN", "STDOUT"}, wantDest: LogDestMixed, wantFac: "local1"},
		{name: "ly-then-ls", args: []string{"-lylocal0", "-ls", "STDIN", "STDOUT"}, wantDest: LogDestStderr},
		{name: "lf-then-ly", args: []string{"-lf", "socat.log", "-ly", "STDIN", "STDOUT"}, wantDest: LogDestSyslog, wantFac: "daemon"},
		{name: "ly-then-lm", args: []string{"-lylocal0", "-lm", "STDIN", "STDOUT"}, wantDest: LogDestMixed, wantFac: "daemon"},
		{name: "lm-then-lylocal0", args: []string{"-lm", "-lylocal0", "STDIN", "STDOUT"}, wantDest: LogDestSyslog, wantFac: "local0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseArgs(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LogDest != tc.wantDest || cfg.LogFile != tc.wantFile || cfg.LogFacility != tc.wantFac {
				t.Fatalf("dest=%d file=%q fac=%q want dest=%d file=%q fac=%q",
					cfg.LogDest, cfg.LogFile, cfg.LogFacility, tc.wantDest, tc.wantFile, tc.wantFac)
			}
		})
	}
}

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
