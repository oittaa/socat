package testutil

import (
	"context"
	"time"
)

// PollInterval is the delay between unsuccessful Until probes.
const PollInterval = 20 * time.Millisecond

// Until calls probe until it returns true, an error, or ctx is done.
// The first probe runs immediately. Later probes wait PollInterval.
func Until(ctx context.Context, probe func() (bool, error)) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	first := true
	for {
		if !first {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
		first = false
		ok, err := probe()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(PollInterval)
	}
}

// BindBusy reports whether a listen/bind failed because the address is in use
// or not exclusive on this OS.
func BindBusy(err error) bool {
	return retryableBindError(err)
}
