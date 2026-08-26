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
	if err := errors.Join(ctrlErr, optionErr); err != nil {
		return err
	}
	markFDLifecycleApplied(f)
	return nil
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
// unique underlying fd in this call. Files already handled by ApplyFDOptions
// are skipped via per-open *os.File identity (not a process-global fd-number
// cache). FileStream R/W/C sharing one unmarked fd still apply once via seen.
func applyFDLifecycleToStream(s parse.Spec, stream relay.Stream) error {
	if !hasFDLifecycleOptions(s) {
		return nil
	}
	seen := make(map[int]struct{})
	for _, t := range streamSyscallConnTargets(stream) {
		if isFDLifecycleApplied(t.file) {
			continue
		}
		var fdErr error
		ctrlErr := t.raw.Control(func(fd uintptr) {
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
	skipOwner := skipDescriptorOwnerOpts(s.Type)
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "perm":
			if skipOwner {
				continue
			}
			if err := applyOnePerm(fd, o); err != nil {
				return err
			}
		case "user":
			if skipOwner {
				continue
			}
			if err := applyOneUser(fd, o); err != nil {
				return err
			}
		case "group":
			if skipOwner {
				continue
			}
			if err := applyOneGroup(fd, o); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyLateLifecycle(fd int, s parse.Spec) error {
	skipTrunc := skipNamedFileFtruncate(s.Type)
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if err := applyOneAppend(fd, o); err != nil {
				return err
			}
		case "ftruncate":
			if skipTrunc {
				continue
			}
			if err := applyOneFtruncate(fd, o); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyOneAppend(fd int, o parse.Option) error {
	enable := optionEnabled(o)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("append: %w", err)
	}
	if enable {
		flags |= unix.O_APPEND
	} else {
		flags &^= unix.O_APPEND
	}
	noteLifecycleSyscall("F_SETFL")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("append: %w", err)
	}
	return nil
}

func applyOneFtruncate(fd int, o parse.Option) error {
	n, err := parseFtruncateOption(o)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("ftruncate: not a regular file")
	}
	noteLifecycleSyscall("ftruncate")
	if err := unix.Ftruncate(fd, n); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	return nil
}

func applyOnePerm(fd int, o parse.Option) error {
	if !o.Has {
		return nil
	}
	mode, err := parseModeT(o.OriginalSpelling(), o.Value)
	if err != nil {
		return err
	}
	noteLifecycleSyscall("fchmod")
	if err := unix.Fchmod(fd, FileModeToUnix(mode)); err != nil {
		return fmt.Errorf("fchmod: %w", err)
	}
	return nil
}

func applyOneUser(fd int, o parse.Option) error {
	uid, hasU, err := resolveUID(optionString(o))
	if err != nil {
		return err
	}
	if !hasU {
		return nil
	}
	noteLifecycleSyscall("fchown")
	if err := unix.Fchown(fd, uid, -1); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}

func applyOneGroup(fd int, o parse.Option) error {
	gid, hasG, err := resolveGID(optionString(o))
	if err != nil {
		return err
	}
	if !hasG {
		return nil
	}
	noteLifecycleSyscall("fchown")
	if err := unix.Fchown(fd, -1, gid); err != nil {
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
