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

// AddressWaitLockPollInterval is classic xiowaitlock's 1s poll for address
// waitlock= (xioopts.c OPT_WAITLOCK sets lock.intervall.tv_sec = 1 at
// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same xiolockfile.c /
// xioopts.c). Cancellation is still checked before each create.
const AddressWaitLockPollInterval = time.Second

// CLILockPollInterval is this port's CLI -W retry interval (100ms). Classic
// -W also uses 1s (socat.c); matching that for -W is a separate change.
const CLILockPollInterval = 100 * time.Millisecond

// DefaultLockPollInterval is the AcquireLockFile fallback when interval <= 0.
const DefaultLockPollInterval = CLILockPollInterval

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
// port reuses the CLI -L/-W O_EXCL implementation. Write/close failure
// unlinks only when lstat still names the created object.
func CreateLockFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) // #nosec G302 G304 -- lockfile=/waitlock=/-L/-W path comes from the user; 0644 matches classic socat
	if err != nil {
		return err
	}
	info, statErr := f.Stat()
	if statErr == nil {
		_ = snapshotRegisteredIdentity(info)
	}
	_, werr := fmt.Fprintf(f, "%d\n", os.Getpid())
	cerr := f.Close()
	if werr != nil || cerr != nil {
		if statErr == nil {
			releaseLockFile(path, info)
		}
		if werr != nil {
			return werr
		}
		return cerr
	}
	return nil
}

// HoldLockFile acquires path (waitlock if wait) and returns an identity-safe
// release used for normal close, failed-open cleanup, and signal-exit unlink.
// interval is the waitlock poll; lockfile= ignores it. Pass
// AddressWaitLockPollInterval for address waitlock= and CLILockPollInterval
// for CLI -W.
func HoldLockFile(ctx context.Context, path string, wait bool, interval time.Duration) (func(), error) {
	if err := AcquireLockFile(ctx, path, wait, interval); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		// Name is gone or unreadable; do not blindly unlink a replacement.
		return nil, err
	}
	if !snapshotRegisteredIdentity(info) {
		return nil, fmt.Errorf("lockfile %s: cannot snapshot identity", path)
	}
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
	return HoldLockFile(ctx, path, wait, AddressWaitLockPollInterval)
}

func addressLockRequest(s parse.Spec) (path string, wait bool, err error) {
	// Classic xioopts.c OPT_LOCKFILE/OPT_WAITLOCK Error()s a second
	// occurrence then continues and overwrites the stored pointer (leaking
	// the first strdup, and still calling xiolock). Do not reproduce that:
	// collect every occurrence first and fail before acquire.
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
