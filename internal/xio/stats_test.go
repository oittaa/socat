package xio

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func TestNewSessionSharesStatsFlagWithForks(t *testing.T) {
	root := NewSession(Options{Statistics: true}, logx.New())
	if root.statsPrinted == nil {
		t.Fatal("NewSession must allocate the shared statistics flag")
	}
	child := root.ForkSession()
	sibling := root.ForkSession()
	if child.statsPrinted != root.statsPrinted || sibling.statsPrinted != root.statsPrinted {
		t.Fatal("forks must share the root statistics flag")
	}
	child.markStatsPrinted()
	if !root.statsAlreadyPrinted() || !sibling.statsAlreadyPrinted() {
		t.Fatal("one child print must be visible to the root and siblings")
	}
}

func TestPrintExitStatsAfterChildTransfer(t *testing.T) {
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Info)
	root := NewSession(Options{Statistics: true, BlockSize: 8192, Linger: 0, LeftToRight: true}, lg)
	child := root.ForkSession()
	left := relay.FDStream{R: strings.NewReader("hi"), W: io.Discard, C: eofNoticeCloser{}}
	right := relay.FDStream{R: eofNoticeEOF{}, W: io.Discard, C: eofNoticeCloser{}}
	if err := transferStreamsOpts(context.Background(), left, right, child, false, false); err != nil {
		t.Fatal(err)
	}
	afterChild := buf.String()
	if !strings.Contains(afterChild, "STATISTICS") {
		t.Fatalf("child transfer must print statistics:\n%s", afterChild)
	}
	if !root.statsAlreadyPrinted() {
		t.Fatal("child transfer must mark the shared root flag")
	}
	n := strings.Count(afterChild, "STATISTICS")
	PrintExitStats(root)
	if strings.Count(buf.String(), "STATISTICS") != n {
		t.Fatalf("PrintExitStats(root) repeated child statistics:\n%s", buf.String())
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
