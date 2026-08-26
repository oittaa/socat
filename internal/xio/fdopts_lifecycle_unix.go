//go:build unix

package xio

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// Descriptor lifecycle options from classic xio-fd.c / applyopt_spec /
// applyopt_fcntl (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same option records):
//
//   - append / o-append: GROUP_FD|GROUP_OPEN, PH_LATE, TYPE_BOOL, OFUNC_FCNTL
//     F_SETFL O_APPEND. applyopt_fcntl GETFL then flag|=O_APPEND or
//     flag&=~O_APPEND, so append=0 clears the bit. Bare append is true.
//   - perm: GROUP_FD|GROUP_NAMED, PH_FD, fchmod(2) on the descriptor.
//   - user / group: GROUP_FD|GROUP_NAMED, PH_FD, fchown(2) on the descriptor.
//   - ftruncate / truncate: GROUP_REG, PH_LATE, ftruncate(2). Fail when the
//     fd is not a regular file (do not silently no-op).
//
// Named OPEN/FILE/CREATE/GOPEN still consume perm= as open(2) mode (classic
// retropt_modet) so umask applies; those types skip fchmod here. Their
// ftruncate stays on the named-file open path to avoid truncating twice and
// to keep Windows working.

// fdLifecycleTestHook is invoked once per unique fd when lifecycle options
// are actually applied. Tests use it to prove WrapCommon does not re-apply
// after ApplyFDOptions (attachTermios-style dedup by fd number).
var fdLifecycleTestHook func(fd int)

var fdLifecycleApplied sync.Map // fd int -> spec identity string

func specLifecycleIdent(s parse.Spec) string {
	return fmt.Sprintf("%s/%p", s.Type, s.Options)
}

func claimFDLifecycle(fd int, s parse.Spec) bool {
	ident := specLifecycleIdent(s)
	if prev, ok := fdLifecycleApplied.Load(fd); ok && prev.(string) == ident {
		return false
	}
	fdLifecycleApplied.Store(fd, ident)
	return true
}

func hasFDLifecycleOptions(s parse.Spec) bool {
	if s.HasOption("append") {
		return true
	}
	if s.HasOption("ftruncate") || s.HasOption("truncate") {
		return true
	}
	if !skipDescriptorOwnerOpts(s.Type) {
		if s.HasOption("perm") || s.HasOption("user") || s.HasOption("group") {
			return true
		}
	}
	return false
}

// skipDescriptorOwnerOpts reports address types that already consume perm=/
// user=/group= as create mode or named chmod/chown (classic retropt_modet /
// ApplyNamedAttrs / ApplyNamedAfterBind). Applying fchmod here would undo
// umask on regular files, fchmod a PTY master instead of the slave, and
// Darwin fchmod(2) on UNIX sockets returns EINVAL.
func skipDescriptorOwnerOpts(addrType string) bool {
	t := strings.ToUpper(addrType)
	switch t {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN", "PIPE", "FIFO", "ECHO", "PTY":
		return true
	}
	if strings.HasPrefix(t, "UNIX") || strings.HasPrefix(t, "ABSTRACT") {
		return true
	}
	return false
}

func skipNamedFileFtruncate(addrType string) bool {
	switch strings.ToUpper(addrType) {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN":
		return true
	default:
		return false
	}
}

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
	if !claimFDLifecycle(fd, s) {
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
// unique underlying fd. WrapCommon uses this for sockets and for streams
// whose openers already called ApplyFDOptions (claimFDLifecycle then no-ops).
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
	o, ok := s.OptionNamed("ftruncate")
	if !ok {
		o, ok = s.OptionNamed("truncate")
	}
	if !ok {
		return nil
	}
	if !o.Has {
		return fmt.Errorf("ftruncate: invalid value %q", o.Value)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("ftruncate: invalid value %q", o.Value)
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
	o, ok := s.OptionNamed("perm")
	if !ok || !o.Has {
		return nil
	}
	mode, err := parseModeT("perm", o.Value)
	if err != nil {
		return err
	}
	if err := unix.Fchmod(fd, FileModeToUnix(mode)); err != nil {
		if socketChmodUnsupported(fd, err) {
			return nil
		}
		return fmt.Errorf("fchmod: %w", err)
	}
	return nil
}

func applyFDOwner(fd int, s parse.Spec) error {
	if skipDescriptorOwnerOpts(s.Type) {
		return nil
	}
	uid, hasU, err := resolveUID(s.OptionValue("user", ""))
	if err != nil {
		return err
	}
	gid, hasG, err := resolveGID(s.OptionValue("group", ""))
	if err != nil {
		return err
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
		if socketChmodUnsupported(fd, err) {
			return nil
		}
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}

// socketChmodUnsupported reports Darwin/BSD fchmod(2)/fchown(2) EINVAL on
// socket fds. ApplyPerm already falls back to path chmod for named sockets
// and PTY slaves; WrapCommon has only the fd. Named UNIX sockets are chmod'd
// via ApplyNamedAfterBind. Do not fail the open (tag-1.8.1.3 Fchmod in
// applyopt_spec would error; this port keeps the named-path chmod that
// already ran).
func socketChmodUnsupported(fd int, err error) bool {
	if err == nil || !errors.Is(err, unix.EINVAL) {
		return false
	}
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFSOCK
}
