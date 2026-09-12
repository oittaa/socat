package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestParseDurationRejectsEmptyAndRange(t *testing.T) {
	if _, err := addrconfig.ParseDuration(""); err == nil || !strings.Contains(err.Error(), "empty duration") {
		t.Fatalf("empty: %v", err)
	}
	if _, err := addrconfig.ParseDuration("NaN"); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("range: %v", err)
	}
}

func TestPrepareRejectsInvalidRetryInterval(t *testing.T) {
	for _, raw := range []string{
		"TCP:127.0.0.1:9,interval=banana",
		"TCP:127.0.0.1:9,interval=-1",
		"TCP:127.0.0.1:9,interval=-1s",
	} {
		s, err := parse.ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PrepareSpec(s); err == nil {
			t.Fatalf("%s: invalid retry interval accepted", raw)
		}
	}
}
