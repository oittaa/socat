package xio

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// DefaultLockPollInterval is the waitlock= / -W retry interval.
// Classic xiowaitlock uses 1s (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same xiolockfile.c).
// This port matches CLI -W (100ms), not classic's 1s.
const DefaultLockPollInterval = 100 * time.Millisecond

// AcquireLockFile creates path with O_EXCL (0644, pid\n). If wait is false and
// the name exists, it returns "lockfile %s exists". If wait is true, it polls
// until the create succeeds or ctx is cancelled. ctx is checked before each
// create so cancellation cannot create the file.
func AcquireLockFile(ctx context.Context, path string, wait bool, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultLockPollInterval
	}
	const transientRetryLimit = time.Second
	contentionObserved := false
	var transientSince time.Time
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := CreateLockFile(path)
		if err == nil {
			return nil
		}
		exists := errors.Is(err, fs.ErrExist)
		transient := wait && contentionObserved && isTransientLockCreateError(err)
		if !exists && !transient {
			return err
		}
		if !wait {
			return fmt.Errorf("lockfile %s exists", path)
		}
		if exists {
			contentionObserved = true
			transientSince = time.Time{}
		} else if transientSince.IsZero() {
			transientSince = time.Now()
		} else if time.Since(transientSince) >= transientRetryLimit {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// CreateLockFile atomically creates path (O_CREATE|O_EXCL) with mode 0644 and
// writes pid\n. Classic xiogetlock uses mkstemp + chmod 0644 + link(2); this
// port reuses the CLI -L/-W O_EXCL implementation.
func CreateLockFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) // #nosec G302 G304 -- lockfile=/waitlock=/-L/-W path comes from the user; 0644 matches classic socat
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(f, "%d\n", os.Getpid())
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(path)
		return cerr
	}
	return nil
}

// HoldLockFile acquires path (waitlock if wait) and returns an identity-safe
// release. The path is registered for signal-exit unlink.
func HoldLockFile(ctx context.Context, path string, wait bool) (func(), error) {
	if err := AcquireLockFile(ctx, path, wait, DefaultLockPollInterval); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = Unlink(path)
		return nil, err
	}
	_ = snapshotRegisteredIdentity(info)
	unreg := RegisterUnlinkPath(path)
	var once sync.Once
	return func() {
		once.Do(func() {
			unreg()
			releaseLockFile(path, info)
		})
	}, nil
}

// releaseLockFile unlinks path only when it still names the acquired object.
//
// Security exception: classic xiounlock (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a) is a blind unlink(2) of the stored
// name. This port skips the name when lstat/os.SameFile shows a replacement.
func releaseLockFile(path string, original os.FileInfo) {
	current, err := os.Lstat(path)
	if err != nil || !sameRegisteredFile(original, current) {
		return
	}
	_ = Unlink(path)
}

// applyAddressLock implements classic PH_INIT GROUP_APPL lockfile=/waitlock=
// (xioopts.c OPT_LOCKFILE/OPT_WAITLOCK at tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree). Call after
// ResolveChdirPaths and before the opener so a failed open still releases and
// relative paths follow chdir=.
func applyAddressLock(ctx context.Context, s parse.Spec) (func(), error) {
	if !s.HasOption("lockfile") && !s.HasOption("waitlock") {
		return nil, nil
	}
	path, wait, err := addressLockRequest(s)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}
	return HoldLockFile(ctx, path, wait)
}

func addressLockRequest(s parse.Spec) (path string, wait bool, err error) {
	seen := false
	for _, o := range s.Options {
		name := parse.CanonicalOptionName(o.Name)
		switch name {
		case "lockfile", "waitlock":
			if seen {
				return "", false, fmt.Errorf("only one use of options lockfile and waitlock allowed")
			}
			seen = true
			if !o.Has || strings.TrimSpace(o.Value) == "" {
				return "", false, fmt.Errorf("option %q requires a value", o.Name)
			}
			path = o.Value
			wait = name == "waitlock"
		}
	}
	return path, wait, nil
}
