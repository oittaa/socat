//go:build unix

package xio

import (
	"errors"
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// fdLifecycleTestHook is invoked each time lifecycle options are applied to
// an fd. Tests use it to observe WrapCommon's per-call same-fd dedup.
var fdLifecycleTestHook func(fd int)

func applyFDLifecycleToFile(f *os.File, s parse.Spec) error {
	if f == nil || !hasFDLifecycleOptions(s) {
		return nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDLifecycleOnFD(int(fd), s)
	})
	return errors.Join(ctrlErr, optionErr)
}

func applyFDLifecycleOnFD(fd int, s parse.Spec) error {
	if !hasFDLifecycleOptions(s) {
		return nil
	}
	if fdLifecycleTestHook != nil {
		fdLifecycleTestHook(fd)
	}
	if err := applyFDPhaseLifecycle(fd, s); err != nil {
		return err
	}
	return applyLateLifecycle(fd, s)
}

// applyFDLifecycleToStream applies descriptor lifecycle options once per
// unique underlying fd in this call. Duplicate application on the same live
// fd (ApplyFDOptions then WrapCommon) is idempotent; fd numbers are not
// cached globally because the kernel reuses them after close.
func applyFDLifecycleToStream(s parse.Spec, stream relay.Stream) error {
	if !hasFDLifecycleOptions(s) {
		return nil
	}
	seen := make(map[int]struct{})
	for _, raw := range streamSyscallConns(stream) {
		var fdErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			n := int(fd)
			if _, ok := seen[n]; ok {
				return
			}
			seen[n] = struct{}{}
			fdErr = applyFDLifecycleOnFD(n, s)
		})
		if err := errors.Join(ctrlErr, fdErr); err != nil {
			return err
		}
	}
	return nil
}

func applyFDPhaseLifecycle(fd int, s parse.Spec) error {
	if err := applyFDPerm(fd, s); err != nil {
		return err
	}
	return applyFDOwner(fd, s)
}

func applyLateLifecycle(fd int, s parse.Spec) error {
	if err := applyFDAppend(fd, s); err != nil {
		return err
	}
	return applyFDFtruncate(fd, s)
}

func applyFDAppend(fd int, s parse.Spec) error {
	enable, present := optionBoolAny(s, "append")
	if !present {
		return nil
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("append: %w", err)
	}
	if enable {
		flags |= unix.O_APPEND
	} else {
		flags &^= unix.O_APPEND
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("append: %w", err)
	}
	return nil
}

func applyFDFtruncate(fd int, s parse.Spec) error {
	if skipNamedFileFtruncate(s.Type) {
		return nil
	}
	n, present, err := parseFtruncateLength(s)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("ftruncate: not a regular file")
	}
	if err := unix.Ftruncate(fd, n); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	return nil
}

func applyFDPerm(fd int, s parse.Spec) error {
	if skipDescriptorOwnerOpts(s.Type) {
		return nil
	}
	o, ok := lastLifecycleOption(s, "perm", "mode")
	if !ok || !o.Has {
		return nil
	}
	mode, err := parseModeT(o.OriginalSpelling(), o.Value)
	if err != nil {
		return err
	}
	if err := unix.Fchmod(fd, FileModeToUnix(mode)); err != nil {
		return fmt.Errorf("fchmod: %w", err)
	}
	return nil
}

func applyFDOwner(fd int, s parse.Spec) error {
	if skipDescriptorOwnerOpts(s.Type) {
		return nil
	}
	var uid, gid int
	var hasU, hasG bool
	var err error
	if o, ok := lastLifecycleOption(s, "user", "uid", "owner"); ok {
		uid, hasU, err = resolveUID(optionString(o))
		if err != nil {
			return err
		}
	}
	if o, ok := lastLifecycleOption(s, "group", "gid"); ok {
		gid, hasG, err = resolveGID(optionString(o))
		if err != nil {
			return err
		}
	}
	if !hasU && !hasG {
		return nil
	}
	u, g := -1, -1
	if hasU {
		u = uid
	}
	if hasG {
		g = gid
	}
	if err := unix.Fchown(fd, u, g); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}

func optionString(o parse.Option) string {
	if !o.Has {
		return "1"
	}
	return o.Value
}
