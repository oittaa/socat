// procan — process analyzer (classic socat companion).
//go:build unix

package main

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	return runWithIO(args, os.Stdout, os.Stderr)
}

func runWithIO(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		switch a {
		case "-h", "-?":
			usage(stdout)
			return 0
		case "-c":
			printCdefs(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "procan: unknown option %q\n", a)
			usage(stderr)
			return 1
		}
	}
	procan(stdout)
	return 0
}

func usage(w io.Writer) {
	fprintln(w, "procan by oittaa — analyze process parameters (Go reimplementation of socat procan)")
	fprintln(w, "Usage: procan [options]")
	fprintln(w, "  -h|-?  help")
	fprintln(w, "  -c     print select compile-time constants (Go equivalents)")
}

func procan(w io.Writer) {
	fprintf(w, "process id = %d\n", os.Getpid())
	fprintf(w, "process parent id = %d\n", os.Getppid())

	// controlling terminal
	var tty string
	if f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		// ttyname via /proc
		if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); err == nil {
			tty = p
		} else {
			tty = "/dev/tty"
		}
		_ = f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		fprintf(w, "controlling terminal: %q\n", tty)
	} else {
		fprintf(w, "controlling terminal: -\n")
	}

	fprintf(w, "process group id = %d\n", unix.Getpgrp())
	if sid, err := unix.Getsid(0); err == nil {
		fprintf(w, "process session id = %d\n", sid)
	}
	if pg, err := unix.IoctlGetInt(0, unix.TIOCGPGRP); err == nil {
		fprintf(w, "process group id if fg process / stdin = %d\n", pg)
	} else {
		fprintf(w, "process group id if fg process / stdin = -1\n")
	}
	if pg, err := unix.IoctlGetInt(1, unix.TIOCGPGRP); err == nil {
		fprintf(w, "process group id if fg process / stdout = %d\n", pg)
	} else {
		fprintf(w, "process group id if fg process / stdout = -1\n")
	}
	if pg, err := unix.IoctlGetInt(2, unix.TIOCGPGRP); err == nil {
		fprintf(w, "process group id if fg process / stderr = %d\n", pg)
	} else {
		fprintf(w, "process group id if fg process / stderr = -1\n")
	}

	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0o600); err == nil {
		fprintln(w, "process has a controlling terminal")
		_ = f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
	} else {
		fprintln(w, "process does not have a controlling terminal")
	}

	fprintf(w, "user id  = %d\n", os.Getuid())
	fprintf(w, "effective user id  = %d\n", os.Geteuid())
	fprintf(w, "group id = %d\n", os.Getgid())
	fprintf(w, "effective group id = %d\n", os.Getegid())

	if u, err := user.Current(); err == nil {
		fprintf(w, "user name = %s\n", u.Username)
	}

	fprintln(w)
	fprintln(w, "RESOURCE LIMITS")
	fprintln(w, "resource                                 current                 maximum")
	printRlimit(w, "cpu time (seconds)", unix.RLIMIT_CPU)
	printRlimit(w, "file size (blocks)", unix.RLIMIT_FSIZE)
	printRlimit(w, "data seg size (kbytes)", unix.RLIMIT_DATA)
	printRlimit(w, "stack size (blocks)", unix.RLIMIT_STACK)
	printRlimit(w, "core file size (blocks)", unix.RLIMIT_CORE)
	printRlimit(w, "max resident set size", unix.RLIMIT_RSS)
	printRlimit(w, "max user processes", unix.RLIMIT_NPROC)
	printRlimit(w, "open files", unix.RLIMIT_NOFILE)
	printRlimit(w, "max locked-in-memory address space", unix.RLIMIT_MEMLOCK)
	printRlimit(w, "virtual memory (kbytes)", unix.RLIMIT_AS)

	// environment (subset / hostan-like)
	fprintln(w)
	fprintln(w, "ENVIRONMENT")
	if h, err := os.Hostname(); err == nil {
		fprintf(w, "hostname = %s\n", h)
	}
	fprintf(w, "working directory = %s\n", mustGetwd())
	if v := os.Getenv("PATH"); v != "" {
		fprintf(w, "PATH = %s\n", v)
	}
	if v := os.Getenv("HOME"); v != "" {
		fprintf(w, "HOME = %s\n", v)
	}
	if v := os.Getenv("SHELL"); v != "" {
		fprintf(w, "SHELL = %s\n", v)
	}
	fprintf(w, "time = %s\n", time.Now().Format(time.RFC3339))

	// Classic procan emits sizeof lines used by test.sh SIZE_T extraction:
	//   SIZE_T=$($PROCAN |grep "^[^[:space:]]*size_t" |awk '{print($3);}')
	fprintln(w)
	fprintf(w, "sizeof(int)       = %d\n", strconv.IntSize/8)
	fprintf(w, "sizeof(long)      = %d\n", int(unsafe.Sizeof(int64(0))))
	fprintf(w, "sizeof(size_t)    = %d\n", int(unsafe.Sizeof(uintptr(0))))
	fprintf(w, "sizeof(off_t)     = %d\n", int(unsafe.Sizeof(int64(0))))
	fprintf(w, "sizeof(time_t)    = %d\n", int(unsafe.Sizeof(int64(0))))
	fprintf(w, "FD_SETSIZE = %d\n", unix.FD_SETSIZE)
}

func printRlimit(w io.Writer, name string, res int) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(res, &lim); err != nil {
		return
	}
	fprintf(w, "%-32s%24s%24s\n", name, rlimStr(lim.Cur), rlimStr(lim.Max))
}

func rlimStr(v uint64) string {
	if v == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return strconv.FormatUint(v, 10)
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "?"
	}
	return wd
}

func printCdefs(w io.Writer) {
	// Classic test.sh greps `^#define NAME value` from procan -c for SOCK_DGRAM,
	// PF_INET6, SOL_SOCKET, SO_REUSEADDR, TCP_MAXSEG, TIOCEXCL, FOPEN_MAX.
	// Emit both human-readable lines and classic-style defines.
	fprintln(w, "/* Go/unix constants (classic-compatible #define lines for test.sh) */")
	fprintf(w, "sizeof(int) ~= %d\n", strconv.IntSize/8)
	// test.sh: SIZE_T=$($PROCAN |grep size_t |awk '{print($3);}')
	fprintf(w, "sizeof(size_t)    = %d\n", int(unsafe.Sizeof(uintptr(0))))
	fprintf(w, "FD_SETSIZE = %d\n", unix.FD_SETSIZE)
	fprintf(w, "PATH_MAX = %d\n", unix.PathMax)

	// Human-readable form
	fprintf(w, "AF_UNIX = %d\n", unix.AF_UNIX)
	fprintf(w, "AF_INET = %d\n", unix.AF_INET)
	fprintf(w, "AF_INET6 = %d\n", unix.AF_INET6)
	fprintf(w, "SOCK_STREAM = %d\n", unix.SOCK_STREAM)
	fprintf(w, "SOCK_DGRAM = %d\n", unix.SOCK_DGRAM)
	fprintf(w, "SOL_SOCKET = %d\n", unix.SOL_SOCKET)
	fprintf(w, "SO_REUSEADDR = %d\n", unix.SO_REUSEADDR)
	fprintf(w, "IPPROTO_TCP = %d\n", unix.IPPROTO_TCP)
	fprintf(w, "IPPROTO_UDP = %d\n", unix.IPPROTO_UDP)

	// Classic #define form (PF_* aliases AF_* on Linux)
	fprintf(w, "#define PF_UNSPEC %d\n", unix.AF_UNSPEC)
	fprintf(w, "#define PF_UNIX %d\n", unix.AF_UNIX)
	fprintf(w, "#define PF_INET %d\n", unix.AF_INET)
	fprintf(w, "#define PF_INET6 %d\n", unix.AF_INET6)
	fprintf(w, "#define AF_UNIX %d\n", unix.AF_UNIX)
	fprintf(w, "#define AF_INET %d\n", unix.AF_INET)
	fprintf(w, "#define AF_INET6 %d\n", unix.AF_INET6)
	fprintf(w, "#define SOCK_STREAM %d\n", unix.SOCK_STREAM)
	fprintf(w, "#define SOCK_DGRAM %d\n", unix.SOCK_DGRAM)
	fprintf(w, "#define SOCK_RAW %d\n", unix.SOCK_RAW)
	fprintf(w, "#define SOCK_SEQPACKET %d\n", unix.SOCK_SEQPACKET)
	fprintf(w, "#define SOL_SOCKET %d\n", unix.SOL_SOCKET)
	fprintf(w, "#define SO_REUSEADDR %d\n", unix.SO_REUSEADDR)
	fprintf(w, "#define IPPROTO_IP %d\n", unix.IPPROTO_IP)
	fprintf(w, "#define IPPROTO_TCP %d\n", unix.IPPROTO_TCP)
	fprintf(w, "#define IPPROTO_UDP %d\n", unix.IPPROTO_UDP)
	fprintf(w, "#define IPPROTO_RAW %d\n", unix.IPPROTO_RAW)
	fprintf(w, "#define TCP_MAXSEG %d\n", unix.TCP_MAXSEG)
	fprintf(w, "#define TIOCEXCL 0x%x\n", unix.TIOCEXCL)
	fprintf(w, "#define FOPEN_MAX 16\n")
	fprintf(w, "#define FD_SETSIZE %d\n", unix.FD_SETSIZE)

	uname := &unix.Utsname{}
	if err := unix.Uname(uname); err == nil {
		fprintf(w, "uname.sysname = %s\n", cstr(uname.Sysname[:]))
		fprintf(w, "uname.release = %s\n", cstr(uname.Release[:]))
		fprintf(w, "uname.machine = %s\n", cstr(uname.Machine[:]))
	}
}

func cstr(b []byte) string {
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return string(b[:i])
}

// Help and status writes: a failure is not actionable.
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func fprintln(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}
