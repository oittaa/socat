package xio

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseDurationValueRejectsEmptyAndRange(t *testing.T) {
	if _, err := ParseDurationValue(""); err == nil || !errors.Is(err, ErrEmptyDuration) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := ParseDurationValue("NaN"); err == nil || !errors.Is(err, ErrDurationOutOfRange) {
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
