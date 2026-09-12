package xio

import (
	"context"
	"fmt"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
)

// WithRetry runs fn until success or policy exhausted / ctx done.
func WithRetry(ctx context.Context, g *Global, policy addrconfig.RetryPolicy, what string, fn func() error) error {
	var last error
	for attempt := uint64(1); policy.MaxAttempts == 0 || attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = fn()
		if last == nil {
			return nil
		}
		if policy.MaxAttempts != 0 && attempt >= policy.MaxAttempts {
			break
		}
		if g != nil && g.Log != nil {
			g.Log.Noticef("%s: %v; retrying in %s", what, last, policy.Interval)
		}
		t := time.NewTimer(policy.Interval)
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
