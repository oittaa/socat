package xio

import (
	"bytes"
	"strings"
	"sync"
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

func TestPrintStatsAtErrorLevelKeepsUnrelatedFilter(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	log.SetLevel(logx.Error)
	PrintStats(log, relay.Stats{BytesLR: 2, BlocksLR: 1}, true, false, true)
	log.Debugf("secret-debug")
	log.Warningf("secret-warning")
	out := buf.String()
	if !strings.Contains(out, "STATISTICS") {
		t.Fatalf("STATISTICS missing at Error level:\n%s", out)
	}
	if strings.Contains(out, "secret-debug") || strings.Contains(out, "secret-warning") {
		t.Fatalf("unrelated messages leaked:\n%s", out)
	}
	if strings.Contains(out, "statistics are experimental") {
		t.Fatalf("experimental warning should stay filtered at Error:\n%s", out)
	}
	if log.Level() != logx.Error {
		t.Fatalf("parent level=%v want Error", log.Level())
	}
}

func TestPrintStatsConcurrentWithLogging(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	log.SetLevel(logx.Warning)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				PrintStats(log, relay.Stats{BytesLR: 1, BlocksLR: 1}, true, true, true)
				log.Warningf("w")
				log.Debugf("d")
				c := log.Clone()
				c.SetLevel(logx.Debug)
				c.Debugf("c")
			}
		}()
	}
	wg.Wait()
	if log.Level() != logx.Warning {
		t.Fatalf("parent level=%v want Warning", log.Level())
	}
}
