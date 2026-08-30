//go:build windows

package relay

import (
	"context"
	"time"

	"golang.org/x/sys/windows"
)

func canPoll() bool { return false }

func idleClockSleep() {
	windows.SleepEx(uint32(idleWatchInterval.Milliseconds()), false)
}

// waitPollRead has no WSAPoll in x/sys/windows. Callers must use canPoll()
// and the SetReadDeadline loop; this stub must not claim the fd is ready.
func waitPollRead(_ int, timeoutMs int) error {
	if timeoutMs > 0 {
		time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
	}
	return errPollIdle
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

func waitWritable(ctx context.Context, _ int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
