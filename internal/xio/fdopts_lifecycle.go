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

// Descriptor lifecycle options walk the command-line list after open, then
// late. Every occurrence is applied, including aliases. Last-wins
// OptionNamed is not used for applying. ApplyFDOptions owns already-open
// files and marks the *os.File so WrapCommon skips it. Fd numbers are not
// cached. OPEN/FILE/CREATE/GOPEN consume perm= as open(2) mode so umask
// applies. Windows hides and rejects ioctl-* and cloexec.

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

// optionPhaseTestHook is invoked at the start of after-open, after-socket,
// after-connect/accept, and late option application. Tests assert ACCEPT-FD
// applies those stages in that order.
var optionPhaseTestHook func(phase string)

func noteOptionPhase(phase string) {
	if hook := optionPhaseTestHook; hook != nil {
		hook(phase)
	}
}

// InstallOptionPhaseHook installs a test observer invoked at the start of
// each option-phase apply. Tests restore the previous hook with the
// returned function.
func InstallOptionPhaseHook(f func(phase string)) func() {
	prev := optionPhaseTestHook
	optionPhaseTestHook = f
	return func() { optionPhaseTestHook = prev }
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
	if hasPlatformFDLifecycleOptions(s) {
		return true
	}
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
		case "cloexec":
			return true
		}
	}
	return false
}

// skipDescriptorOwnerOption reports call sites that consume one owner option
// as create mode or named chmod/chown. Applying fchmod here would undo umask
// on regular files and fchmod a PTY master instead of the slave.
func skipDescriptorOwnerOption(s parse.Spec, name string) bool {
	t := strings.ToUpper(s.Type)
	switch t {
	case "OPEN", "FILE", "GOPEN", "PTY":
		return true
	case "CREATE", "CREAT":
		// CREATE consumes perm as the creat(2) mode, but user and group
		// still apply to the opened descriptor.
		return name == "perm"
	case "PIPE", "FIFO":
		// A named FIFO consumes perm as mkfifo/open mode and applies ownership
		// to the filesystem entry. Anonymous PIPE/FIFO (and ECHO) have no name;
		// their owner options belong on the pipe descriptor.
		return len(s.Params) > 0 && s.Params[0] != ""
	case "EXEC", "SYSTEM", "SHELL":
		// With pty, perm/user/group apply to the slave node. The master
		// retains descriptor-only options such as append.
		return s.BoolOption("pty") || s.BoolOption("ptmx") || s.BoolOption("openpty")
	}
	if strings.HasPrefix(t, "POSIXMQ") {
		// perm= is mq_open(3) mode, not fchmod. user=/group= remain
		// descriptor options and must not become silent no-ops.
		return name == "perm"
	}
	if unixStreamListenPHFDOwner(s) {
		// Filesystem listeners apply after-open owner options to the name.
		// Abstract listeners apply them to the listening descriptor before
		// accept. In both cases the accepted stream must not apply them again.
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

// namedFilesystemUnixPHFD is true after bind of a filesystem UNIX listen/recv
// name. Abstract names have no directory entry; owner options apply to the
// descriptor instead.
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

// skipNamedFileAsync reports named opens that OR O_ASYNC into open(2).
// CREATE uses creat(2) and applies async with F_SETFL late instead.
func skipNamedFileAsync(addrType string) bool {
	switch strings.ToUpper(addrType) {
	case "OPEN", "FILE", "GOPEN":
		return true
	default:
		return false
	}
}

// lastLifecycleOption returns the last command-line option whose canonical
// name matches any of names. Used for lookups that need a single value
// (open-mode, tests); apply walks every occurrence instead.
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
		// Missing value defaults to 1 (man page for seek options).
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
// occurrence in command-line order. Production named OPEN/CREATE/GOPEN apply
// that walk through ApplyFDOptions so lseek and perm-late share the same phase.
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
