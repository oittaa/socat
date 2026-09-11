package xio

import (
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestPreparedRetryIntervallAlias(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,retry=1,intervall=2.5")
	if err != nil {
		t.Fatal(err)
	}
	p, err := PrepareSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Config.Common.Retry.Policy().Interval; got != 2500*time.Millisecond {
		t.Fatalf("interval=%s want 2.5s", got)
	}
}
