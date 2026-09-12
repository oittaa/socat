//go:build linux || darwin

package cli

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
)

func TestParseArgsRejectsUnknownFacility(t *testing.T) {
	_, err := ParseArgs([]string{"-lynotafacility", "STDIN", "STDOUT"})
	if err == nil || !strings.Contains(err.Error(), `unknown syslog facility "notafacility"`) {
		t.Fatalf("err=%v", err)
	}
}

func TestParseArgsSyslogFacility(t *testing.T) {
	cfg, err := ParseArgs([]string{"-ly", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogDest != LogDestSyslog || cfg.LogFacility != logx.FacilityDaemon {
		t.Fatalf("omitted facility dest=%v facility=%v", cfg.LogDest, cfg.LogFacility)
	}

	cfg, err = ParseArgs([]string{"-lyLOCAL0", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogDest != LogDestSyslog || cfg.LogFacility != logx.FacilityLocal0 {
		t.Fatalf("LOCAL0 dest=%v facility=%v", cfg.LogDest, cfg.LogFacility)
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
