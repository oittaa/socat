package addr

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// retryPolicy from classic retry=N, forever, interval=seconds.
type retryPolicy struct {
	// maxAttempts: 1 = no retry, 0 = forever
	maxAttempts int
	interval    time.Duration
}

func parseRetry(s parse.Spec) retryPolicy {
	p := retryPolicy{maxAttempts: 1, interval: time.Second}
	if s.BoolOption("forever") {
		p.maxAttempts = 0
	}
	if v := s.OptionValue("retry", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			// classic: retry=N means N retries after the first try → N+1 attempts
			if n < 0 {
				p.maxAttempts = 0
			} else {
				p.maxAttempts = n + 1
			}
		}
	}
	if v := s.OptionValue("interval", ""); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			p.interval = time.Duration(f * float64(time.Second))
		} else if d, err := time.ParseDuration(v); err == nil {
			p.interval = d
		}
	}
	return p
}

// withRetry runs fn until success or policy exhausted / ctx done.
func withRetry(ctx context.Context, s parse.Spec, g *Global, what string, fn func() error) error {
	p := parseRetry(s)
	var last error
	for attempt := 1; p.maxAttempts == 0 || attempt <= p.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = fn()
		if last == nil {
			return nil
		}
		if p.maxAttempts != 0 && attempt >= p.maxAttempts {
			break
		}
		if g != nil && g.Log != nil {
			g.Log.Noticef("%s: %v; retrying in %s", what, last, p.interval)
		}
		t := time.NewTimer(p.interval)
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
