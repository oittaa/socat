// procan — process analyzer.
//go:build linux || darwin

package main

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"
	"unsafe"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/outbuf"
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
			if err := usage(stdout); err != nil {
				return 1
			}
			return 0
		case "-c":
			if err := printCdefs(stdout); err != nil {
				return 1
			}
			return 0
		default:
			if _, err := fmt.Fprintf(stderr, "procan: unknown option %q\n", a); err != nil {
				return 1
			}
			_ = usage(stderr)
			return 1
		}
	}
	if err := procan(stdout); err != nil {
		return 1
	}
	return 0
}

func usage(w io.Writer) error {
	var b outbuf.Buf
	b.Println("procan by oittaa — analyze process parameters (Go reimplementation of socat procan)")
	b.Println("Usage: procan [options]")
	b.Println("  -h|-?  help")
	b.Println("  -c     print select compile-time constants (Go equivalents)")
	return b.Flush(w)
}

func procan(w io.Writer) error {
	var b outbuf.Buf
	b.Printf("process id = %d\n", os.Getpid())
	b.Printf("process parent id = %d\n", os.Getppid())

	// controlling terminal
	var tty string
	if f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		// ttyname via /proc
		if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); err == nil {
			tty = p
		} else {
			tty = "/dev/tty"
		}
		logx.CloseQuiet(f)
		b.Printf("controlling terminal: %q\n", tty)
	} else {
		b.Printf("controlling terminal: -\n")
	}

	b.Printf("process group id = %d\n", unix.Getpgrp())
	if sid, err := unix.Getsid(0); err == nil {
		b.Printf("process session id = %d\n", sid)
	}
	if pg, err := unix.IoctlGetInt(0, unix.TIOCGPGRP); err == nil {
		b.Printf("process group id if fg process / stdin = %d\n", pg)
	} else {
		b.Printf("process group id if fg process / stdin = -1\n")
	}
	if pg, err := unix.IoctlGetInt(1, unix.TIOCGPGRP); err == nil {
		b.Printf("process group id if fg process / stdout = %d\n", pg)
	} else {
		b.Printf("process group id if fg process / stdout = -1\n")
	}
	if pg, err := unix.IoctlGetInt(2, unix.TIOCGPGRP); err == nil {
		b.Printf("process group id if fg process / stderr = %d\n", pg)
	} else {
		b.Printf("process group id if fg process / stderr = -1\n")
	}

	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0o600); err == nil {
		b.Println("process has a controlling terminal")
		logx.CloseQuiet(f)
	} else {
		b.Println("process does not have a controlling terminal")
	}

	b.Printf("user id  = %d\n", os.Getuid())
	b.Printf("effective user id  = %d\n", os.Geteuid())
	b.Printf("group id = %d\n", os.Getgid())
	b.Printf("effective group id = %d\n", os.Getegid())

	if u, err := user.Current(); err == nil {
		b.Printf("user name = %s\n", u.Username)
	}

	b.Println()
	b.Println("RESOURCE LIMITS")
	b.Println("resource                                 current                 maximum")
	printRlimit(&b, "cpu time (seconds)", unix.RLIMIT_CPU)
	printRlimit(&b, "file size (blocks)", unix.RLIMIT_FSIZE)
	printRlimit(&b, "data seg size (kbytes)", unix.RLIMIT_DATA)
	printRlimit(&b, "stack size (blocks)", unix.RLIMIT_STACK)
	printRlimit(&b, "core file size (blocks)", unix.RLIMIT_CORE)
	printRlimit(&b, "max resident set size", unix.RLIMIT_RSS)
	printRlimit(&b, "max user processes", unix.RLIMIT_NPROC)
	printRlimit(&b, "open files", unix.RLIMIT_NOFILE)
	printRlimit(&b, "max locked-in-memory address space", unix.RLIMIT_MEMLOCK)
	printRlimit(&b, "virtual memory (kbytes)", unix.RLIMIT_AS)

	// environment (hostname, cwd, PATH, HOME, SHELL)
	b.Println()
	b.Println("ENVIRONMENT")
	if h, err := os.Hostname(); err == nil {
		b.Printf("hostname = %s\n", h)
	}
	b.Printf("working directory = %s\n", mustGetwd())
	if v := os.Getenv("PATH"); v != "" {
		b.Printf("PATH = %s\n", v)
	}
	if v := os.Getenv("HOME"); v != "" {
		b.Printf("HOME = %s\n", v)
	}
	if v := os.Getenv("SHELL"); v != "" {
		b.Printf("SHELL = %s\n", v)
	}
	b.Printf("time = %s\n", time.Now().Format(time.RFC3339))

	// sizeof lines; test.sh greps size_t for SIZE_T extraction:
	//   SIZE_T=$($PROCAN |grep "^[^[:space:]]*size_t" |awk '{print($3);}')
	b.Println()
	b.Printf("sizeof(int)       = %d\n", strconv.IntSize/8)
	b.Printf("sizeof(long)      = %d\n", int(unsafe.Sizeof(int64(0))))
	b.Printf("sizeof(size_t)    = %d\n", int(unsafe.Sizeof(uintptr(0))))
	b.Printf("sizeof(off_t)     = %d\n", int(unsafe.Sizeof(int64(0))))
	b.Printf("sizeof(time_t)    = %d\n", int(unsafe.Sizeof(int64(0))))
	b.Printf("FD_SETSIZE = %d\n", unix.FD_SETSIZE)
	return b.Flush(w)
}

func printRlimit(b *outbuf.Buf, name string, res int) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(res, &lim); err != nil {
		return
	}
	b.Printf("%-32s%24s%24s\n", name, rlimStr(lim.Cur), rlimStr(lim.Max))
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

func printCdefs(w io.Writer) error {
	var b outbuf.Buf
	// procan -c emits #define NAME value; test.sh greps SOCK_DGRAM, PF_INET6,
	// SOL_SOCKET, SO_REUSEADDR, TCP_MAXSEG, TIOCEXCL, FOPEN_MAX.
	// Also emit human-readable NAME = value lines.
	b.Println("/* Go/unix constants (classic-compatible #define lines for test.sh) */")
	b.Printf("sizeof(int) ~= %d\n", strconv.IntSize/8)
	// test.sh: SIZE_T=$($PROCAN |grep size_t |awk '{print($3);}')
	b.Printf("sizeof(size_t)    = %d\n", int(unsafe.Sizeof(uintptr(0))))
	b.Printf("FD_SETSIZE = %d\n", unix.FD_SETSIZE)
	b.Printf("PATH_MAX = %d\n", unix.PathMax)

	// Human-readable form
	b.Printf("AF_UNIX = %d\n", unix.AF_UNIX)
	b.Printf("AF_INET = %d\n", unix.AF_INET)
	b.Printf("AF_INET6 = %d\n", unix.AF_INET6)
	b.Printf("SOCK_STREAM = %d\n", unix.SOCK_STREAM)
	b.Printf("SOCK_DGRAM = %d\n", unix.SOCK_DGRAM)
	b.Printf("SOL_SOCKET = %d\n", unix.SOL_SOCKET)
	b.Printf("SO_REUSEADDR = %d\n", unix.SO_REUSEADDR)
	b.Printf("IPPROTO_TCP = %d\n", unix.IPPROTO_TCP)
	b.Printf("IPPROTO_UDP = %d\n", unix.IPPROTO_UDP)

	// #define NAME value form (PF_* aliases AF_* on Linux)
	b.Printf("#define PF_UNSPEC %d\n", unix.AF_UNSPEC)
	b.Printf("#define PF_UNIX %d\n", unix.AF_UNIX)
	b.Printf("#define PF_INET %d\n", unix.AF_INET)
	b.Printf("#define PF_INET6 %d\n", unix.AF_INET6)
	b.Printf("#define AF_UNIX %d\n", unix.AF_UNIX)
	b.Printf("#define AF_INET %d\n", unix.AF_INET)
	b.Printf("#define AF_INET6 %d\n", unix.AF_INET6)
	b.Printf("#define SOCK_STREAM %d\n", unix.SOCK_STREAM)
	b.Printf("#define SOCK_DGRAM %d\n", unix.SOCK_DGRAM)
	b.Printf("#define SOCK_RAW %d\n", unix.SOCK_RAW)
	b.Printf("#define SOCK_SEQPACKET %d\n", unix.SOCK_SEQPACKET)
	b.Printf("#define SOL_SOCKET %d\n", unix.SOL_SOCKET)
	b.Printf("#define SO_REUSEADDR %d\n", unix.SO_REUSEADDR)
	b.Printf("#define IPPROTO_IP %d\n", unix.IPPROTO_IP)
	b.Printf("#define IPPROTO_TCP %d\n", unix.IPPROTO_TCP)
	b.Printf("#define IPPROTO_UDP %d\n", unix.IPPROTO_UDP)
	b.Printf("#define IPPROTO_RAW %d\n", unix.IPPROTO_RAW)
	b.Printf("#define TCP_MAXSEG %d\n", unix.TCP_MAXSEG)
	b.Printf("#define TIOCEXCL 0x%x\n", unix.TIOCEXCL)
	b.Printf("#define FOPEN_MAX 16\n")
	b.Printf("#define FD_SETSIZE %d\n", unix.FD_SETSIZE)

	uname := &unix.Utsname{}
	if err := unix.Uname(uname); err == nil {
		b.Printf("uname.sysname = %s\n", cstr(uname.Sysname[:]))
		b.Printf("uname.release = %s\n", cstr(uname.Release[:]))
		b.Printf("uname.machine = %s\n", cstr(uname.Machine[:]))
	}
	return b.Flush(w)
}

func cstr(b []byte) string {
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return string(b[:i])
}
