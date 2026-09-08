package xio

import (
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseTimevalWrapsDurationErrors(t *testing.T) {
	if _, err := parseTimeval(""); err == nil || err.Error() != "empty timeout" {
		t.Fatalf("empty: %v", err)
	}
	if _, err := parseTimeval("NaN"); err == nil || err.Error() != "timeout out of range" {
		t.Fatalf("range: %v", err)
	}
}

func TestParseRetryInvalidIntervalKeepsDefault(t *testing.T) {
	for _, raw := range []string{
		"TCP:127.0.0.1:9,interval=banana",
		"TCP:127.0.0.1:9,interval=-1",
		"TCP:127.0.0.1:9,interval=-1s",
	} {
		s, err := parse.ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		p := ParseRetry(s)
		if p.Interval != time.Second {
			t.Fatalf("%s interval=%s want 1s", raw, p.Interval)
		}
	}
}
