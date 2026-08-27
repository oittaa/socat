package xio

import (
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseRetryIntervallAlias(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,retry=1,intervall=2.5")
	if err != nil {
		t.Fatal(err)
	}
	p := ParseRetry(s)
	if p.Interval != 2500*time.Millisecond {
		t.Fatalf("interval=%s want 2.5s", p.Interval)
	}
}

func TestWantCRNLAliasLastWins(t *testing.T) {
	on, err := parse.ParseSpec("TCP:127.0.0.1:9,crlf")
	if err != nil {
		t.Fatal(err)
	}
	if !wantCRNL(on) {
		t.Fatal("crlf alias should enable CRNL conversion")
	}
	off, err := parse.ParseSpec("TCP:127.0.0.1:9,crlf,crnl=0")
	if err != nil {
		t.Fatal(err)
	}
	if wantCRNL(off) {
		t.Fatal("last-wins crnl=0 should disable CRNL conversion")
	}
}
