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
