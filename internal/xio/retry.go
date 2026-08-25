package xio

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// RetryPolicy from classic retry=N, forever, interval=seconds.
type RetryPolicy struct {
	// maxAttempts: 1 = no retry, 0 = forever
	MaxAttempts int
	Interval    time.Duration
}

func ParseRetry(s parse.Spec) RetryPolicy {
	p := RetryPolicy{MaxAttempts: 1, Interval: time.Second}
	if s.BoolOption("forever") {
		p.MaxAttempts = 0
	}
	if v := s.OptionValue("retry", ""); v != "" {
		n, err := ParseIntAny(v)
		if err == nil {
			// classic: retry=N means N retries after the first try → N+1 attempts
			if n < 0 {
				p.MaxAttempts = 0
			} else {
				p.MaxAttempts = n + 1
			}
		}
	}
	if v := s.OptionValue("interval", ""); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			p.Interval = time.Duration(f * float64(time.Second))
		} else if d, err := time.ParseDuration(v); err == nil {
			p.Interval = d
		}
	}
	return p
}

// WithRetry runs fn until success or policy exhausted / ctx done.
func WithRetry(ctx context.Context, s parse.Spec, g *Global, what string, fn func() error) error {
	p := ParseRetry(s)
	var last error
	for attempt := 1; p.MaxAttempts == 0 || attempt <= p.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = fn()
		if last == nil {
			return nil
		}
		if p.MaxAttempts != 0 && attempt >= p.MaxAttempts {
			break
		}
		if g != nil && g.Log != nil {
			g.Log.Noticef("%s: %v; retrying in %s", what, last, p.Interval)
		}
		t := time.NewTimer(p.Interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	if last == nil {
		return fmt.Errorf("%s: failed", what)
	}
	return last
}
