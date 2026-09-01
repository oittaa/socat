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

// AddressWaitLockPollInterval is the 1s poll for address waitlock=.
// Cancellation is still checked before each create.
const AddressWaitLockPollInterval = time.Second

// CLILockPollInterval is the CLI -W retry interval (1s), matching
// address waitlock=.
const CLILockPollInterval = time.Second

// DefaultLockPollInterval is the AcquireLockFile fallback when interval <= 0.
const DefaultLockPollInterval = CLILockPollInterval

// lockfileAfterCreateHook runs after a successful CreateLockFile inside
// HoldLockFile and before identity verification / signal-cleanup registration.
// Tests replace the pathname here; production leaves it nil.
var lockfileAfterCreateHook func(path string)

// AcquireLockFile creates path with O_EXCL (0644, pid\n). If wait is false and
// the name exists, it returns "lockfile %s exists". If wait is true, it polls
// until the create succeeds or ctx is cancelled. ctx is checked before each
// create so cancellation cannot create the file. The returned FileInfo is
// f.Stat() of the created descriptor while it was still open.
func AcquireLockFile(ctx context.Context, path string, wait bool, interval time.Duration) (os.FileInfo, error) {
	if interval <= 0 {
		interval = DefaultLockPollInterval
	}
	const transientRetryLimit = time.Second
	contentionObserved := false
	var transientSince time.Time
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := CreateLockFile(path)
		if err == nil {
			return info, nil
		}
		exists := errors.Is(err, fs.ErrExist)
		transient := wait && contentionObserved && isTransientLockCreateError(err)
		if !exists && !transient {
			return nil, err
		}
		if !wait {
			return nil, fmt.Errorf("lockfile %s exists", path)
		}
		if exists {
			contentionObserved = true
			transientSince = time.Time{}
		} else if transientSince.IsZero() {
			transientSince = time.Now()
		} else if time.Since(transientSince) >= transientRetryLimit {
			return nil, err
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
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// CreateLockFile atomically creates path (O_CREATE|O_EXCL) with mode 0644 and
// writes pid\n. OpenFile's mode is umask-masked, so this fchmod(0644)s the
// still-open descriptor. Identity is f.Stat() while that fd is open; a later
// Lstat must still name the same object before success is returned.
// Write/close/chmod failure unlinks only when lstat still names that object.
func CreateLockFile(path string) (os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) // #nosec G302 G304 -- lockfile=/waitlock=/-L/-W path comes from the user; 0644 lockfile mode
	if err != nil {
		return nil, err
	}
	_, werr := fmt.Fprintf(f, "%d\n", os.Getpid())
	if werr == nil {
		// fchmod(0644) after write, before close. os.OpenFile's 0644 is
		// umask-masked; this restores the lock mode.
		werr = f.Chmod(0o644)
	}
	info, statErr := f.Stat()
	if statErr == nil {
		_ = SnapshotFileIdentity(info)
	}
	cerr := f.Close()
	if werr != nil || cerr != nil || statErr != nil {
		if statErr == nil {
			releaseLockFile(path, info)
		}
		if werr != nil {
			return nil, werr
		}
		if cerr != nil {
			return nil, cerr
		}
		return nil, statErr
	}
	if err := verifyLockIdentity(path, info); err != nil {
		return nil, err
	}
	return info, nil
}

// HoldLockFile acquires path (waitlock if wait) and returns an identity-safe
// release used for normal close, failed-open cleanup, and signal-exit unlink.
// interval is the waitlock poll; lockfile= ignores it. Pass
// AddressWaitLockPollInterval for address waitlock= and CLILockPollInterval
// for CLI -W. Signal cleanup is registered with the create-time FileInfo,
// not a second Lstat of whatever currently occupies the name.
func HoldLockFile(ctx context.Context, path string, wait bool, interval time.Duration) (func(), error) {
	info, err := AcquireLockFile(ctx, path, wait, interval)
	if err != nil {
		return nil, err
	}
	if h := lockfileAfterCreateHook; h != nil {
		h(path)
	}
	if err := verifyLockIdentity(path, info); err != nil {
		return nil, err
	}
	unreg := RegisterUnlinkPathIdentity(path, info)
	if err := verifyLockIdentity(path, info); err != nil {
		unreg()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			unreg()
			releaseLockFile(path, info)
		})
	}, nil
}

func verifyLockIdentity(path string, original os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil || !sameRegisteredFile(original, current) {
		return fmt.Errorf("lockfile %s: acquired name was replaced", path)
	}
	return nil
}

// releaseLockFile unlinks path only when it still names the acquired object.
//
// Security exception: unlink only when the name still refers to the acquired
// object. A replacement at the same path is left in place.
func releaseLockFile(path string, original os.FileInfo) {
	UnlinkIfSameFile(path, original)
}

// applyAddressLock applies lockfile=/waitlock= after ResolveChdirPaths and
// before the opener so a failed open still releases and relative paths follow
// chdir=.
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
	return HoldLockFile(ctx, path, wait, AddressWaitLockPollInterval)
}

func addressLockRequest(s parse.Spec) (path string, wait bool, err error) {
	// Reject a second lockfile=/waitlock= before acquire.
	var locks []parse.Option
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "lockfile", "waitlock":
			locks = append(locks, o)
		}
	}
	if len(locks) == 0 {
		return "", false, nil
	}
	if len(locks) > 1 {
		return "", false, fmt.Errorf("only one use of options lockfile and waitlock allowed")
	}
	o := locks[0]
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return "", false, fmt.Errorf("option %q requires a value", o.Name)
	}
	return o.Value, parse.CanonicalOptionName(o.Name) == "waitlock", nil
}
