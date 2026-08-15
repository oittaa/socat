package xio

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func TestPrintStatsClassicLines(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	log.SetLevel(logx.Warning)
	PrintStats(log, relay.Stats{BytesLR: 3, BlocksLR: 1, BytesRL: 3, BlocksRL: 1}, true, true, true)
	out := buf.String()
	if !strings.Contains(out, "statistics are experimental") {
		t.Fatalf("missing experimental warn:\n%s", out)
	}
	n := strings.Count(out, "STATISTICS")
	if n != 2 {
		t.Fatalf("want 2 STATISTICS lines, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "left to right:") || !strings.Contains(out, "right to left:") {
		t.Fatalf("missing directions:\n%s", out)
	}
	if !strings.Contains(out, "packets(s)") || !strings.Contains(out, "byte(s)") {
		t.Fatalf("missing classic wording:\n%s", out)
	}
}

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
