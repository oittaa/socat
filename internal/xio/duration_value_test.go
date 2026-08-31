package xio

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestParseDurationValue(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   time.Duration
		err    error
		errAny bool
	}{
		{name: "seconds", in: "2", want: 2 * time.Second},
		{name: "fractional", in: "0.5", want: 500 * time.Millisecond},
		{name: "trimmed", in: " 1.5 ", want: 1500 * time.Millisecond},
		{name: "unit", in: "250ms", want: 250 * time.Millisecond},
		{name: "empty", in: "", err: ErrEmptyDuration},
		{name: "whitespace", in: "  ", err: ErrEmptyDuration},
		{name: "nan", in: "NaN", err: ErrDurationOutOfRange},
		{name: "inf", in: "+Inf", err: ErrDurationOutOfRange},
		{name: "overflow", in: "1e100", err: ErrDurationOutOfRange},
		{name: "garbage", in: "banana", errAny: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDurationValue(tc.in)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("error=%v want %v", err, tc.err)
				}
				return
			}
			if tc.errAny {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

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

func TestIsTimeoutErrDelegates(t *testing.T) {
	if IsTimeoutErr(os.ErrDeadlineExceeded) != relay.IsTimeoutErr(os.ErrDeadlineExceeded) {
		t.Fatal("xio.IsTimeoutErr must match relay.IsTimeoutErr")
	}
}
