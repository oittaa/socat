//go:build unix

package xio

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

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
	// Hidden wrappers (UDP-RECV, POSIX MQ, QUIC, …) are not syscall.Conn, or
	// embed one after the parent already applied on the raw socket. Skip here
	// so a promoted SyscallConn cannot double-apply. Never treat a visible
	// stream with no fd as success.
	if wrapHidesDescriptor(s) {
		return nil
	}
	targets := streamSyscallConnTargets(stream)
	if len(targets) == 0 {
		return fmt.Errorf("append/perm/user/group/ftruncate: stream does not expose a descriptor")
	}
	seen := make(map[int]struct{})
	for _, t := range targets {
		if isFDLifecycleApplied(t.file) || isConnLifecycleApplied(t.conn) {
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
		markFDLifecycleApplied(t.file)
		markConnLifecycleApplied(t.conn)
	}
	return nil
}

// ApplyFDLifecycleToConn applies PH_FD then PH_LATE on a live syscall.Conn
// (UDP/UNIX/QUIC transport, before wrapping). Marks the conn so WrapCommon
// does not apply twice on streams that still expose the same object.
func ApplyFDLifecycleToConn(c syscall.Conn, s parse.Spec) error {
	if c == nil || !hasFDLifecycleOptions(s) {
		return nil
	}
	if isConnLifecycleApplied(c) {
		return nil
	}
	raw, err := c.SyscallConn()
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
	markConnLifecycleApplied(c)
	return nil
}

// ApplyFDPhaseLifecycleToConn applies only classic PH_FD owner options to a
// descriptor that is not the eventual transfer stream. Abstract UNIX stream
// listeners use this before accept; PH_LATE remains for the accepted socket.
func ApplyFDPhaseLifecycleToConn(c syscall.Conn, s parse.Spec) error {
	if c == nil {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDPhaseLifecycleAll(int(fd), s)
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDLifecycleToPacketConn applies descriptor lifecycle on a UDP
// PacketConn (QUIC transport) before quic-go wrapping. Rejects enabled
// options when the conn does not expose a socket.
func ApplyFDLifecycleToPacketConn(pc net.PacketConn, s parse.Spec) error {
	if pc == nil || !hasFDLifecycleOptions(s) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("append/perm/user/group/ftruncate: packet connection does not expose a socket")
	}
	return ApplyFDLifecycleToConn(sc, s)
}

// ApplyFDLifecycleOnFD applies PH_FD then PH_LATE on a raw descriptor
// (POSIX MQ mqd, listen sockets). Caller applies once on the parent.
func ApplyFDLifecycleOnFD(fd int, s parse.Spec) error {
	return applyFDLifecycleOnFD(fd, s)
}

func applyFDPhaseLifecycle(fd int, s parse.Spec) error {
	return applyFDPhaseLifecycleOptions(fd, s, true)
}

// applyFDPhaseLifecycleAll is for the actual descriptor that owns PH_FD
// options even when the eventual transfer stream must skip them. Abstract
// UNIX listeners are configured here before accept; accepted children must
// not receive the same perm/user/group options again.
func applyFDPhaseLifecycleAll(fd int, s parse.Spec) error {
	return applyFDPhaseLifecycleOptions(fd, s, false)
}

func applyFDPhaseLifecycleOptions(fd int, s parse.Spec, honorTargetSkip bool) error {
	for _, o := range s.Options {
		name := parse.CanonicalOptionName(o.Name)
		switch name {
		case "perm":
			if honorTargetSkip && skipDescriptorOwnerOption(s, name) {
				continue
			}
			if err := applyOnePerm(fd, o); err != nil {
				return err
			}
		case "user":
			if honorTargetSkip && skipDescriptorOwnerOption(s, name) {
				continue
			}
			if err := applyOneUser(fd, o); err != nil {
				return err
			}
		case "group":
			if honorTargetSkip && skipDescriptorOwnerOption(s, name) {
				continue
			}
			if err := applyOneGroup(fd, o); err != nil {
				return err
			}
		case "flock":
			if err := applyOneFlock(fd, o, unix.LOCK_EX); err != nil {
				return err
			}
		case "flock-nb":
			if err := applyOneFlock(fd, o, unix.LOCK_EX|unix.LOCK_NB); err != nil {
				return err
			}
		case "flock-sh":
			if err := applyOneFlock(fd, o, unix.LOCK_SH); err != nil {
				return err
			}
		case "flock-sh-nb":
			if err := applyOneFlock(fd, o, unix.LOCK_SH|unix.LOCK_NB); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyLateLifecycle(fd int, s parse.Spec) error {
	skipAppend := skipNamedFileAppend(s.Type)
	skipAsync := skipNamedFileAsync(s.Type)
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if skipAppend {
				continue
			}
			if err := applyOneAppend(fd, o); err != nil {
				return err
			}
		case "async":
			if skipAsync {
				continue
			}
			if err := applyOneAsync(fd, o); err != nil {
				return err
			}
		case "ftruncate":
			if err := applyOneFtruncate(fd, o); err != nil {
				return err
			}
		case "lseek":
			if err := applyOneLseek(fd, o, io.SeekStart); err != nil {
				return err
			}
		case "seek-cur":
			if err := applyOneLseek(fd, o, io.SeekCurrent); err != nil {
				return err
			}
		case "seek-end":
			if err := applyOneLseek(fd, o, io.SeekEnd); err != nil {
				return err
			}
		case "perm-late":
			if err := applyOnePerm(fd, o); err != nil {
				return err
			}
		case "user-late":
			if err := applyOneUser(fd, o); err != nil {
				return err
			}
		case "group-late":
			if err := applyOneGroup(fd, o); err != nil {
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

func applyOneAsync(fd int, o parse.Option) error {
	enable := optionEnabled(o)
	if enable && !FeatureFDAsync {
		return fmt.Errorf("%s: not supported on this platform", o.OriginalSpelling())
	}
	if !FeatureFDAsync {
		return nil
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	if enable {
		flags |= fdAsyncFlag
	} else {
		flags &^= fdAsyncFlag
	}
	noteLifecycleSyscall("F_SETFL")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	return nil
}

func applyOneFlock(fd int, o parse.Option, how int) error {
	if !optionEnabled(o) {
		return nil
	}
	if !FeatureFlock {
		return fmt.Errorf("%s: not supported on this platform", o.OriginalSpelling())
	}
	noteLifecycleSyscall("flock")
	if err := flockFD(fd, how); err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	return nil
}

func applyOneLseek(fd int, o parse.Option, whence int) error {
	off, err := parseLseekOffset(o)
	if err != nil {
		return err
	}
	noteLifecycleSyscall("lseek")
	if _, err := unix.Seek(fd, off, whence); err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
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
	v, err := requiredLifecycleOptionValue(o)
	if err != nil {
		return err
	}
	uid, hasU, err := resolveUID(v)
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
	v, err := requiredLifecycleOptionValue(o)
	if err != nil {
		return err
	}
	gid, hasG, err := resolveGID(v)
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
