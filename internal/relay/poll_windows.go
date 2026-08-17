//go:build windows

package relay

import (
	"context"
	"time"
)

// waitPollRead has no WSAPoll in x/sys/windows. Sleep, then let Read run.
func waitPollRead(_ int, timeoutMs int) error {
	if timeoutMs > 0 {
		time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
	}
	return nil
}

func waitReadableAndWritable(ctx context.Context, _, _ int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(100 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
