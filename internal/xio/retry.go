package xio

import (
	"context"
	"fmt"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
)

// RetryPolicyFromContext returns the static retry policy prepared for the
// address currently being opened.
func RetryPolicyFromContext(ctx context.Context) addrconfig.RetryPolicy {
	if config, ok := PreparedConfig(ctx); ok {
		return config.Common.Retry.Policy()
	}
	return addrconfig.RetryPolicy{MaxAttempts: 1, Interval: time.Second}
}

// WithRetry runs fn until success or policy exhausted / ctx done.
func WithRetry(ctx context.Context, g *Global, what string, fn func() error) error {
	p := RetryPolicyFromContext(ctx)
	var last error
	for attempt := uint64(1); p.MaxAttempts == 0 || attempt <= p.MaxAttempts; attempt++ {
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
