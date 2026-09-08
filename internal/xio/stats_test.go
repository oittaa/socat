package xio

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func TestPrintStatsNotStarted(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	PrintStats(log, relay.Stats{}, true, true, false)
	if !strings.Contains(buf.String(), "transfer engine not yet started") {
		t.Fatalf("got %q", buf.String())
	}
	if strings.Contains(buf.String(), "STATISTICS") {
		t.Fatal("should not print STATISTICS before start")
	}
}

func TestPrintStatsUnidirectional(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	log.SetLevel(logx.Warning)
	PrintStats(log, relay.Stats{BytesLR: 4, BlocksLR: 1}, true, false, true)
	out := buf.String()
	if strings.Count(out, "STATISTICS") != 1 {
		t.Fatalf("want 1 line for -u:\n%s", out)
	}
	if strings.Contains(out, "right to left") {
		t.Fatalf("unexpected RTL:\n%s", out)
	}
}

func TestPrintStatsDoesNotChangeParentLevel(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	log.SetLevel(logx.Warning)
	PrintStats(log, relay.Stats{BytesLR: 1, BlocksLR: 1}, true, false, true)
	if log.Level() != logx.Warning {
		t.Fatalf("parent level=%v want Warning", log.Level())
	}
	if !strings.Contains(buf.String(), "STATISTICS") {
		t.Fatalf("missing STATISTICS:\n%s", buf.String())
	}
}
