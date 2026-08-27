package xio

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"weak"

	"github.com/oittaa/socat/internal/parse"
)

// Descriptor lifecycle options from classic xio-fd.c / applyopt_spec /
// applyopt_fcntl (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same option records):
//
//   - append / o-append: GROUP_FD|GROUP_OPEN, PH_LATE, TYPE_BOOL, OFUNC_FCNTL
//     F_SETFL O_APPEND. applyopt_fcntl GETFL then flag|=O_APPEND or
//     flag&=~O_APPEND, so append=0 clears the bit. Bare append is true.
//   - async / o-async: GROUP_OPEN|GROUP_FD, PH_LATE, OFUNC_FCNTL F_SETFL
//     O_ASYNC. Named OPEN/GOPEN also OR O_ASYNC at open(2) (_xioopen_open).
//   - perm / mode: GROUP_FD|GROUP_NAMED, PH_FD, fchmod(2) on the descriptor.
//     Classic xioopts.c IF_ANY("mode", &opt_perm).
//   - perm-late: GROUP_FD, PH_LATE, fchmod(2) after PH_FD perm.
//   - user / uid / owner, group / gid: GROUP_FD|GROUP_NAMED, PH_FD, fchown(2).
//   - user-late / uid-l, group-late / gid-l: GROUP_FD, PH_LATE.
//   - ftruncate / truncate / ftruncate32 / ftruncate64: GROUP_REG, PH_LATE,
//     ftruncate(2). Fail when the fd is not a regular file.
//   - lseek / seek-cur / seek-end (and 32/64 aliases): GROUP_REG|GROUP_BLK,
//     PH_LATE, lseek(2). Last-wins across aliases via command-line order.
//   - flock / flock-nb / flock-sh / flock-sh-nb: GROUP_FD, PH_FD, flock(2).
//     Independent of setlk* fcntl locks (fileopen/lock.go).
//   - o-noatime / noatime: GROUP_FD|GROUP_OPEN, PH_FD, F_SETFL O_NOATIME (Linux).
//   - f-setpipe-sz / pipesz: GROUP_FIFO, PH_FD, F_SETPIPE_SZ (Linux).
//   - fs-* / ext2-* / ext3-* ioctl flags: GROUP_REG, PH_FD,
//     OFUNC_IOCTL_MASK_LONG FS_IOC_GETFLAGS/SETFLAGS (Linux; xio-fs.c).
//   - ioctl-void / ioctl, ioctl-int, ioctl-intp, ioctl-bin, ioctl-string:
//     GROUP_FD, PH_FD, OFUNC_IOCTL_GENERIC (xio-fd.c / applyopt_ioctl_generic).
//     Unix including Darwin; not Linux-only. Windows hides and rejects.
//
// Classic applyopts walks every matching option in original command-line
// order for one phase (PH_FD then PH_LATE). Each occurrence is applied,
// including alias/canonical mixtures (mode with perm, uid/owner with user,
// gid with group, truncate/ftruncate32/64 with ftruncate, lseek64 with
// seek). Last-wins OptionNamed lookup is not used for applying.
//
// Named OPEN/FILE/CREATE/GOPEN still consume perm= as open(2) mode (classic
// retropt_modet) so umask applies; those types skip fchmod here. ftruncate
// on those types shares this PH_LATE walk with lseek/perm-late/async so
// command-line order is preserved (it is not applied a second time on the
// named-file open path).
//
// ApplyFDOptions is the owner for already-open files (STDIN/STDOUT/STDERR/
// FD:n, EXEC child pipes). It records per-open *os.File identity so
// WrapCommon skips those same files. Fd numbers are not cached: the kernel
// reuses them after close.

// lifecycleSyscallTestHook is invoked immediately before fchmod/fchown/
// F_SETFL/ftruncate (and the Windows ftruncate path). Tests assert
// exactly-once apply after ApplyFDOptions then WrapCommon, and command-line
// order of repeated options.
var lifecycleSyscallTestHook func(op string)

func noteLifecycleSyscall(op string) {
	if hook := lifecycleSyscallTestHook; hook != nil {
		hook(op)
	}
}

// InstallLifecycleSyscallHook installs a test observer invoked immediately
// before each lifecycle syscall (F_SETFL, ftruncate, fchmod, fchown, chmod,
// chown). Tests restore the previous hook with the returned function.
func InstallLifecycleSyscallHook(f func(op string)) func() {
	prev := lifecycleSyscallTestHook
	lifecycleSyscallTestHook = f
	return func() { lifecycleSyscallTestHook = prev }
}

// fdLifecycleAppliedFiles is per-open state keyed by *os.File identity, not
// by fd number. A closed file's number may be reused by a new *os.File; that
// new object is a different key and still receives lifecycle options.
var fdLifecycleAppliedFiles sync.Map // weak.Pointer[os.File] -> struct{}
var fdLifecycleAppliedConns sync.Map // weak.Pointer[net.UDPConn|UnixConn|TCPConn|IPConn] -> struct{}

func markFDLifecycleApplied(f *os.File) {
	if f == nil {
		return
	}
	wp := weak.Make(f)
	fdLifecycleAppliedFiles.Store(wp, struct{}{})
	runtime.AddCleanup(f, func(wp weak.Pointer[os.File]) {
		fdLifecycleAppliedFiles.Delete(wp)
	}, wp)
}

func isFDLifecycleApplied(f *os.File) bool {
	if f == nil {
		return false
	}
	_, ok := fdLifecycleAppliedFiles.Load(weak.Make(f))
	return ok
}

func markConnLifecycleApplied(c syscall.Conn) {
	if c == nil {
		return
	}
	switch v := c.(type) {
	case *os.File:
		markFDLifecycleApplied(v)
	case *net.UDPConn:
		markWeakConn(v)
	case *net.UnixConn:
		markWeakConn(v)
	case *net.TCPConn:
		markWeakConn(v)
	case *net.IPConn:
		markWeakConn(v)
	}
}

func isConnLifecycleApplied(c syscall.Conn) bool {
	if c == nil {
		return false
	}
	switch v := c.(type) {
	case *os.File:
		return isFDLifecycleApplied(v)
	case *net.UDPConn:
		return isWeakConnApplied(v)
	case *net.UnixConn:
		return isWeakConnApplied(v)
	case *net.TCPConn:
		return isWeakConnApplied(v)
	case *net.IPConn:
		return isWeakConnApplied(v)
	default:
		return false
	}
}

func markWeakConn[T any](p *T) {
	if p == nil {
		return
	}
	wp := weak.Make(p)
	fdLifecycleAppliedConns.Store(wp, struct{}{})
	runtime.AddCleanup(p, func(wp weak.Pointer[T]) {
		fdLifecycleAppliedConns.Delete(wp)
	}, wp)
}

func isWeakConnApplied[T any](p *T) bool {
	if p == nil {
		return false
	}
	_, ok := fdLifecycleAppliedConns.Load(weak.Make(p))
	return ok
}

func hasFDLifecycleOptions(s parse.Spec) bool {
	skipAppend := skipNamedFileAppend(s.Type)
	skipAsync := skipNamedFileAsync(s.Type)
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if !skipAppend {
				return true
			}
		case "async":
			if !skipAsync {
				return true
			}
		case "ftruncate", "lseek", "seek-cur", "seek-end":
			return true
		case "perm", "user", "group":
			if !skipDescriptorOwnerOption(s, parse.CanonicalOptionName(o.Name)) {
				return true
			}
		case "perm-late", "user-late", "group-late":
			return true
		case "flock", "flock-nb", "flock-sh", "flock-sh-nb":
			return true
		case "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string":
			return true
		}
	}
	return false
}

// skipDescriptorOwnerOption reports call sites that consume one owner option
// as create mode or named chmod/chown (classic retropt_modet /
// applyopts_named PH_FD). Applying fchmod here would undo umask on regular
// files and fchmod a PTY master instead of the slave.
//
// Classic tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba (official
// master af5388c898c7bb60997935aee93c223deba60c4a is the same tree):
// applyopts_named(PH_FD) is used after bind on a filesystem UNIX-LISTEN /
// UNIX-RECV / UNIX-RECVFROM name (xio-listen.c, xio-socket.c). ABSTRACT
// endpoints and UNIX-CONNECT apply PH_FD to the socket descriptor
// (_xioopen_connect / abstract listen branch). Do not skip those.
func skipDescriptorOwnerOption(s parse.Spec, name string) bool {
	t := strings.ToUpper(s.Type)
	switch t {
	case "OPEN", "FILE", "GOPEN", "PTY":
		return true
	case "CREATE", "CREAT":
		// CREATE consumes perm as the creat(2) mode, but classic applies user
		// and group to the opened descriptor through applyopts2(PH_FD).
		return name == "perm"
	case "PIPE", "FIFO":
		// A named FIFO consumes perm as mkfifo/open mode and applies ownership
		// to the filesystem entry. Anonymous PIPE/FIFO (and ECHO) have no name;
		// their GROUP_FD options belong on the pipe descriptor.
		return len(s.Params) > 0 && s.Params[0] != ""
	case "EXEC", "SYSTEM", "SHELL":
		// With pty, classic moves GROUP_NAMED perm/user/group to the slave
		// node. The master retains FD-only options such as append.
		return s.BoolOption("pty")
	}
	if strings.HasPrefix(t, "POSIXMQ") {
		// perm= is mq_open(3) mode (classic retropt_mode), not fchmod. user=/
		// group= remain descriptor options and must not become silent no-ops.
		return name == "perm"
	}
	if unixStreamListenPHFDOwner(s) {
		// Filesystem listeners apply PH_FD to the name. Abstract listeners
		// apply it to the listening descriptor before accept. In both cases
		// the accepted stream must not apply owner options again.
		return true
	}
	return namedFilesystemUnixPHFD(s)
}

func unixStreamListenPHFDOwner(s parse.Spec) bool {
	switch strings.ToUpper(s.Type) {
	case "UNIX-LISTEN", "UNIX-L", "ABSTRACT-LISTEN", "ABSTRACT-L":
		return true
	default:
		return false
	}
}

// namedFilesystemUnixPHFD is classic applyopts_named(PH_FD) after bind of a
// filesystem UNIX listen/recv name. Abstract names have no directory entry
// (xio-listen.c sun_path[0]=='\0' uses applyopts PH_FD on the descriptor).
func namedFilesystemUnixPHFD(s parse.Spec) bool {
	t := strings.ToUpper(s.Type)
	switch t {
	case "UNIX-LISTEN", "UNIX-L", "UNIX-RECV", "UNIX-RECVFROM":
	default:
		return false
	}
	if len(s.Params) > 0 && IsAbstract(s.Params[0]) {
		return false
	}
	return true
}

// wrapHidesDescriptor reports stream types whose WrapCommon view is not a
// syscall.Conn (datagram/QUIC/POSIX MQ wrappers; relay would splice those
// fds). Lifecycle options are applied on the parent socket or mqd before
// wrapping. Never treat an accepted option as a silent no-op: other types
// with no discoverable fd are rejected.
func wrapHidesDescriptor(s parse.Spec) bool {
	t := strings.ToUpper(s.Type)
	if strings.HasPrefix(t, "QUIC") || strings.HasPrefix(t, "POSIXMQ") {
		return true
	}
	if strings.HasPrefix(t, "UDP") || strings.HasPrefix(t, "IP") {
		return true
	}
	switch t {
	case "UNIX-SENDTO", "UNIX-SEND", "UNIX-RECV", "UNIX-RECVFROM", "UNIX-DATAGRAM",
		"ABSTRACT-SENDTO", "ABSTRACT-SEND", "ABSTRACT-RECV", "ABSTRACT-RECVFROM":
		return true
	}
	return false
}

func skipNamedFileAppend(addrType string) bool {
	switch strings.ToUpper(addrType) {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN":
		return true
	default:
		return false
	}
}

// skipNamedFileAsync reports named opens that OR O_ASYNC into open(2)
// (classic _xioopen_open retropt_bool OPT_O_ASYNC). CREATE uses creat(2)
// and applies async with F_SETFL at PH_LATE instead.
func skipNamedFileAsync(addrType string) bool {
	switch strings.ToUpper(addrType) {
	case "OPEN", "FILE", "GOPEN":
		return true
	default:
		return false
	}
}

// lastLifecycleOption returns the last command-line option whose canonical
// name matches any of names (classic last-option-wins across aliases). Used
// for lookups that need a single value (open-mode, tests); apply walks every
// occurrence instead.
func lastLifecycleOption(s parse.Spec, names ...string) (parse.Option, bool) {
	want := make(map[string]struct{}, len(names))
	for _, name := range names {
		want[parse.CanonicalOptionName(name)] = struct{}{}
	}
	for i := len(s.Options) - 1; i >= 0; i-- {
		n := parse.CanonicalOptionName(s.Options[i].Name)
		if _, ok := want[n]; ok {
			return s.Options[i], true
		}
	}
	return parse.Option{}, false
}

func parseFtruncateOption(o parse.Option) (int64, error) {
	name := o.OriginalSpelling()
	if !o.Has {
		return 0, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	return n, nil
}

func parseLseekOffset(o parse.Option) (int64, error) {
	name := o.OriginalSpelling()
	if !o.Has {
		// Classic TYPE_OFF32/TYPE_OFF64 defaults a missing value to 1; the
		// official man page calls this out explicitly for seek options.
		return 1, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	return n, nil
}

func parseFtruncateLength(s parse.Spec) (int64, bool, error) {
	o, ok := lastLifecycleOption(s, "ftruncate", "truncate", "ftruncate32", "ftruncate64")
	if !ok {
		return 0, false, nil
	}
	n, err := parseFtruncateOption(o)
	if err != nil {
		return 0, true, err
	}
	return n, true, nil
}

func requiredLifecycleOptionValue(o parse.Option) (string, error) {
	v := strings.TrimSpace(o.Value)
	if !o.Has || v == "" {
		return "", fmt.Errorf("%s: value required", o.OriginalSpelling())
	}
	return v, nil
}

// ApplyNamedFileFtruncate applies every ftruncate/truncate/ftruncate32/64
// occurrence in command-line order (classic applyopts PH_LATE). Production
// named OPEN/CREATE/GOPEN apply that walk through ApplyFDOptions so lseek
// and perm-late share the same phase; this helper remains for isolated tests.
func ApplyNamedFileFtruncate(f *os.File, s parse.Spec) error {
	if f == nil {
		return nil
	}
	for _, o := range s.Options {
		if parse.CanonicalOptionName(o.Name) != "ftruncate" {
			continue
		}
		n, err := parseFtruncateOption(o)
		if err != nil {
			return err
		}
		noteLifecycleSyscall("ftruncate")
		if err := f.Truncate(n); err != nil {
			return fmt.Errorf("ftruncate: %w", err)
		}
	}
	return nil
}
