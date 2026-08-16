// procan — process analyzer (classic socat companion).
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
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "-?":
			usage(os.Stdout)
			return 0
		case a == "-c":
			printCdefs(os.Stdout)
			return 0
		default:
			fmt.Fprintf(os.Stderr, "procan: unknown option %q\n", a)
			usage(os.Stderr)
			return 1
		}
	}
	procan(os.Stdout)
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "procan by oittaa — analyze process parameters (Go reimplementation of socat procan)")
	fmt.Fprintln(w, "Usage: procan [options]")
	fmt.Fprintln(w, "  -h|-?  help")
	fmt.Fprintln(w, "  -c     print select compile-time constants (Go equivalents)")
}

func procan(w io.Writer) {
	fmt.Fprintf(w, "process id = %d\n", os.Getpid())
	fmt.Fprintf(w, "process parent id = %d\n", os.Getppid())

	// controlling terminal
	var tty string
	if f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		if name, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGDEV); err == nil {
			_ = name
		}
		// ttyname via /proc
		if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); err == nil {
			tty = p
		} else {
			tty = "/dev/tty"
		}
		f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		fmt.Fprintf(w, "controlling terminal: %q\n", tty)
	} else {
		fmt.Fprintf(w, "controlling terminal: -\n")
	}

	fmt.Fprintf(w, "process group id = %d\n", unix.Getpgrp())
	if sid, err := unix.Getsid(0); err == nil {
		fmt.Fprintf(w, "process session id = %d\n", sid)
	}
	if pg, err := unix.IoctlGetInt(0, unix.TIOCGPGRP); err == nil {
		fmt.Fprintf(w, "process group id if fg process / stdin = %d\n", pg)
	} else {
		fmt.Fprintf(w, "process group id if fg process / stdin = -1\n")
	}
	if pg, err := unix.IoctlGetInt(1, unix.TIOCGPGRP); err == nil {
		fmt.Fprintf(w, "process group id if fg process / stdout = %d\n", pg)
	} else {
		fmt.Fprintf(w, "process group id if fg process / stdout = -1\n")
	}
	if pg, err := unix.IoctlGetInt(2, unix.TIOCGPGRP); err == nil {
		fmt.Fprintf(w, "process group id if fg process / stderr = %d\n", pg)
	} else {
		fmt.Fprintf(w, "process group id if fg process / stderr = -1\n")
	}

	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0o600); err == nil {
		fmt.Fprintln(w, "process has a controlling terminal")
		f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
	} else {
		fmt.Fprintln(w, "process does not have a controlling terminal")
	}

	fmt.Fprintf(w, "user id  = %d\n", os.Getuid())
	fmt.Fprintf(w, "effective user id  = %d\n", os.Geteuid())
	fmt.Fprintf(w, "group id = %d\n", os.Getgid())
	fmt.Fprintf(w, "effective group id = %d\n", os.Getegid())

	if u, err := user.Current(); err == nil {
		fmt.Fprintf(w, "user name = %s\n", u.Username)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "RESOURCE LIMITS")
	fmt.Fprintln(w, "resource                                 current                 maximum")
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
	fmt.Fprintln(w)
	fmt.Fprintln(w, "ENVIRONMENT")
	if h, err := os.Hostname(); err == nil {
		fmt.Fprintf(w, "hostname = %s\n", h)
	}
	fmt.Fprintf(w, "working directory = %s\n", mustGetwd())
	if v := os.Getenv("PATH"); v != "" {
		fmt.Fprintf(w, "PATH = %s\n", v)
	}
	if v := os.Getenv("HOME"); v != "" {
		fmt.Fprintf(w, "HOME = %s\n", v)
	}
	if v := os.Getenv("SHELL"); v != "" {
		fmt.Fprintf(w, "SHELL = %s\n", v)
	}
	fmt.Fprintf(w, "time = %s\n", time.Now().Format(time.RFC3339))

	// Classic procan emits sizeof lines used by test.sh SIZE_T extraction:
	//   SIZE_T=$($PROCAN |grep "^[^[:space:]]*size_t" |awk '{print($3);}')
	fmt.Fprintln(w)
	fmt.Fprintf(w, "sizeof(int)       = %d\n", strconv.IntSize/8)
	fmt.Fprintf(w, "sizeof(long)      = %d\n", int(unsafe.Sizeof(int64(0))))
	fmt.Fprintf(w, "sizeof(size_t)    = %d\n", int(unsafe.Sizeof(uintptr(0))))
	fmt.Fprintf(w, "sizeof(off_t)     = %d\n", int(unsafe.Sizeof(int64(0))))
	fmt.Fprintf(w, "sizeof(time_t)    = %d\n", int(unsafe.Sizeof(int64(0))))
	fmt.Fprintf(w, "FD_SETSIZE = %d\n", unix.FD_SETSIZE)
}

func printRlimit(w io.Writer, name string, res int) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(res, &lim); err != nil {
		return
	}
	fmt.Fprintf(w, "%-32s%24s%24s\n", name, rlimStr(lim.Cur), rlimStr(lim.Max))
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
	fmt.Fprintln(w, "/* Go/unix constants (classic-compatible #define lines for test.sh) */")
	fmt.Fprintf(w, "sizeof(int) ~= %d\n", strconv.IntSize/8)
	// test.sh: SIZE_T=$($PROCAN |grep size_t |awk '{print($3);}')
	fmt.Fprintf(w, "sizeof(size_t)    = %d\n", int(unsafe.Sizeof(uintptr(0))))
	fmt.Fprintf(w, "FD_SETSIZE = %d\n", unix.FD_SETSIZE)
	fmt.Fprintf(w, "PATH_MAX = %d\n", unix.PathMax)

	// Human-readable form
	fmt.Fprintf(w, "AF_UNIX = %d\n", unix.AF_UNIX)
	fmt.Fprintf(w, "AF_INET = %d\n", unix.AF_INET)
	fmt.Fprintf(w, "AF_INET6 = %d\n", unix.AF_INET6)
	fmt.Fprintf(w, "SOCK_STREAM = %d\n", unix.SOCK_STREAM)
	fmt.Fprintf(w, "SOCK_DGRAM = %d\n", unix.SOCK_DGRAM)
	fmt.Fprintf(w, "SOL_SOCKET = %d\n", unix.SOL_SOCKET)
	fmt.Fprintf(w, "SO_REUSEADDR = %d\n", unix.SO_REUSEADDR)
	fmt.Fprintf(w, "IPPROTO_TCP = %d\n", unix.IPPROTO_TCP)
	fmt.Fprintf(w, "IPPROTO_UDP = %d\n", unix.IPPROTO_UDP)

	// Classic #define form (PF_* aliases AF_* on Linux)
	fmt.Fprintf(w, "#define PF_UNSPEC %d\n", unix.AF_UNSPEC)
	fmt.Fprintf(w, "#define PF_UNIX %d\n", unix.AF_UNIX)
	fmt.Fprintf(w, "#define PF_INET %d\n", unix.AF_INET)
	fmt.Fprintf(w, "#define PF_INET6 %d\n", unix.AF_INET6)
	fmt.Fprintf(w, "#define AF_UNIX %d\n", unix.AF_UNIX)
	fmt.Fprintf(w, "#define AF_INET %d\n", unix.AF_INET)
	fmt.Fprintf(w, "#define AF_INET6 %d\n", unix.AF_INET6)
	fmt.Fprintf(w, "#define SOCK_STREAM %d\n", unix.SOCK_STREAM)
	fmt.Fprintf(w, "#define SOCK_DGRAM %d\n", unix.SOCK_DGRAM)
	fmt.Fprintf(w, "#define SOCK_RAW %d\n", unix.SOCK_RAW)
	fmt.Fprintf(w, "#define SOCK_SEQPACKET %d\n", unix.SOCK_SEQPACKET)
	fmt.Fprintf(w, "#define SOL_SOCKET %d\n", unix.SOL_SOCKET)
	fmt.Fprintf(w, "#define SO_REUSEADDR %d\n", unix.SO_REUSEADDR)
	fmt.Fprintf(w, "#define IPPROTO_IP %d\n", unix.IPPROTO_IP)
	fmt.Fprintf(w, "#define IPPROTO_TCP %d\n", unix.IPPROTO_TCP)
	fmt.Fprintf(w, "#define IPPROTO_UDP %d\n", unix.IPPROTO_UDP)
	fmt.Fprintf(w, "#define IPPROTO_RAW %d\n", unix.IPPROTO_RAW)
	fmt.Fprintf(w, "#define TCP_MAXSEG %d\n", unix.TCP_MAXSEG)
	fmt.Fprintf(w, "#define TIOCEXCL 0x%x\n", unix.TIOCEXCL)
	fmt.Fprintf(w, "#define FOPEN_MAX 16\n")
	fmt.Fprintf(w, "#define FD_SETSIZE %d\n", unix.FD_SETSIZE)

	uname := &unix.Utsname{}
	if err := unix.Uname(uname); err == nil {
		fmt.Fprintf(w, "uname.sysname = %s\n", cstr(uname.Sysname[:]))
		fmt.Fprintf(w, "uname.release = %s\n", cstr(uname.Release[:]))
		fmt.Fprintf(w, "uname.machine = %s\n", cstr(uname.Machine[:]))
	}
}

func cstr(b []byte) string {
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return string(b[:i])
}
