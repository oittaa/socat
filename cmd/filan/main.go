//go:build linux || darwin

// filan — file descriptor analyzer.
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

type filanConfig struct {
	followSymlinks bool
	rawOutput      bool
	style          int
	singleFD       bool
	m, n           int
	filename       string
	waittime       time.Duration
	outfname       string
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	return runWithIO(args, os.Stdout, os.Stderr)
}

func runWithIO(args []string, stdout, stderr io.Writer) int {
	cfg := filanConfig{
		m: 0,
		n: 1024, // practical default; FD_SETSIZE varies
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			if err := writeMsg(stderr, "filan: unexpected argument %q\n", a); err != nil {
				return 1
			}
			_ = usage(stderr)
			return 1
		}
		switch {
		case a == "-h" || a == "-?":
			if err := usage(stdout); err != nil {
				return 1
			}
			return 0
		case a == "-L":
			cfg.followSymlinks = true
		case a == "-s":
			cfg.style = 1
		case a == "-r":
			cfg.rawOutput = true
		case a == "-d":
			// verbosity ignored for now
		case strings.HasPrefix(a, "-i"):
			v, err := takeArg(a, "i", args, &i)
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			fd, err := strconv.Atoi(v)
			if err != nil {
				if err := writeMsg(stderr, "filan: bad -i %q\n", v); err != nil {
					return 1
				}
				return 1
			}
			cfg.m, cfg.n = fd, fd
			cfg.singleFD = true
		case strings.HasPrefix(a, "-n"):
			v, err := takeArg(a, "n", args, &i)
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			num, err := strconv.Atoi(v)
			if err != nil {
				if err := writeMsg(stderr, "filan: bad -n %q\n", v); err != nil {
					return 1
				}
				return 1
			}
			cfg.n = num
		case strings.HasPrefix(a, "-f"):
			v, err := takeArg(a, "f", args, &i)
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			cfg.filename = v
		case strings.HasPrefix(a, "-T"):
			v, err := takeArg(a, "T", args, &i)
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			sec, err := strconv.ParseFloat(v, 64)
			if err != nil {
				if err := writeMsg(stderr, "filan: bad -T %q\n", v); err != nil {
					return 1
				}
				return 1
			}
			cfg.waittime = time.Duration(sec * float64(time.Second))
		case strings.HasPrefix(a, "-o"):
			v, err := takeArg(a, "o", args, &i)
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			cfg.outfname = v
		default:
			if err := writeMsg(stderr, "filan: unknown option %q\n", a); err != nil {
				return 1
			}
			_ = usage(stderr)
			return 1
		}
	}

	out := stdout
	if cfg.outfname != "" {
		f, err := openOut(cfg.outfname)
		if err != nil {
			if err := writeMsg(stderr, "filan: %v\n", err); err != nil {
				return 1
			}
			return 1
		}
		if f != os.Stdout && f != os.Stderr && f != os.Stdin {
			defer logx.CloseQuiet(f)
		}
		out = f
	}

	if cfg.waittime > 0 {
		time.Sleep(cfg.waittime)
	}

	var report outbuf.Buf
	if cfg.filename != "" {
		if err := cfg.filanFile(cfg.filename, &report); err != nil {
			if err := writeMsg(stderr, "filan: %v\n", err); err != nil {
				return 1
			}
			return 1
		}
		if err := report.Flush(out); err != nil {
			return 1
		}
		return 0
	}

	if cfg.singleFD {
		cfg.n = cfg.m + 1
	} else if cfg.n == 0 {
		// -n0 analyzes fd 0 only; test.sh greps stdin pipe capacity.
		cfg.n = 1
	}
	// Header line; test.sh LISTEN_KEEPALIVE skips it with tail -n +2.
	if cfg.style != 1 {
		report.Println("  FD  typedeviceinodemodelinksuidgidrdevsizeblksizeblocksatimemtimectimecloexecflagssigownsigio")
	}
	for fd := cfg.m; fd < cfg.n; fd++ {
		if cfg.style == 1 {
			fdname(fd, &report)
		} else {
			cfg.filanFD(fd, &report)
		}
	}
	if err := report.Flush(out); err != nil {
		return 1
	}
	return 0
}

func takeArg(a, key string, args []string, i *int) (string, error) {
	prefix := "-" + key
	if a == prefix {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("option %s requires an argument", prefix)
		}
		*i++
		return args[*i], nil
	}
	return a[len(prefix):], nil
}

func openOut(name string) (*os.File, error) {
	switch name {
	case "stdin":
		return os.Stdin, nil
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	}
	if strings.HasPrefix(name, "+") {
		fd, err := strconv.Atoi(name[1:])
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	return os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) // #nosec G302 G304 G703 -- filan -o writes the report to the path the user gave; 0644 is a normal report file
}

func usage(w io.Writer) error {
	var b outbuf.Buf
	b.Println("filan by oittaa — analyze file descriptors (Go reimplementation of socat filan)")
	b.Println("Usage: filan [options]")
	b.Println("  -h|-?        help")
	b.Println("  -i<fdnum>    only analyze this fd")
	b.Println("  -n<fdnum>    analyze fds 0..fdnum-1")
	b.Println("  -s           simple output")
	b.Println("  -f<filename> analyze filesystem entry")
	b.Println("  -T<seconds>  wait before analyzing")
	b.Println("  -r           raw time/rdev output")
	b.Println("  -L           follow symlinks")
	b.Println("  -o<filename> output file")
	return b.Flush(w)
}

func writeMsg(w io.Writer, format string, a ...any) error {
	_, err := fmt.Fprintf(w, format, a...)
	return err
}

func (cfg *filanConfig) filanFile(path string, b *outbuf.Buf) error {
	var st unix.Stat_t
	var err error
	if cfg.followSymlinks {
		err = unix.Stat(path, &st)
	} else {
		err = unix.Lstat(path, &st)
	}
	if err != nil {
		return err
	}
	fd := -1
	// Do not open sockets or symlinks: opening a socket path fails; opening a
	// symlink would follow it and lose the link type without -L. LINKTARGET is
	// printed later when fd stays -1.
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFSOCK, unix.S_IFLNK:
		// leave fd = -1
	default:
		f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0) // #nosec G304 G703 -- filan opens the path or fd the user asked to inspect
		if err == nil {
			fd = int(f.Fd())
			defer logx.CloseQuiet(f)
		}
	}
	cfg.printStat(-1, fd, &st, b)
	// FILANSYMLINK: after lstat of a symlink path, append LINKTARGET=... with no space before the keyword.
	if !cfg.followSymlinks && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		if target, err := os.Readlink(path); err == nil {
			b.Printf("LINKTARGET=%s", target)
		}
	}
	b.Println()
	return nil
}

func (cfg *filanConfig) filanFD(fd int, b *outbuf.Buf) {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	if err != nil {
		return // skip closed FDs silently so gaps in the range stay quiet
	}
	cfg.printStat(fd, fd, &st, b)

	// cloexec / flags
	cloexec, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	flags, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	b.Printf("\t%d\tx%06x", cloexec, flags)
	if own, err := unix.FcntlInt(uintptr(fd), unix.F_GETOWN, 0); err == nil {
		b.Printf("\t%d", own)
	}
	// socket extras
	if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
		printSocket(fd, b)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFIFO {
		printPipeSize(fd, b)
	}
	// try path from /proc
	if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
		b.Printf("\t%s", p)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFCHR {
		if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil {
			b.Printf(" terminal window size:   %dx%d terminal window pixels: %dx%d",
				ws.Col, ws.Row, ws.Xpixel, ws.Ypixel)
		}
	}
	b.Println()
}

func (cfg *filanConfig) printStat(dynfd, statfd int, st *unix.Stat_t, b *outbuf.Buf) {
	fdshow := dynfd
	if fdshow < 0 {
		fdshow = statfd
	}
	devStr := fmt.Sprintf("%d,%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	if cfg.rawOutput {
		devStr = fmt.Sprintf("%d", st.Dev)
	}
	b.Printf("%4d: %s\t%s\t%d\t%06o\t%d\t%d\t%d",
		fdshow,
		fileTypeString(uint32(st.Mode)),
		devStr,
		st.Ino,
		st.Mode,
		st.Nlink,
		st.Uid,
		st.Gid,
	)
	if st.Mode&unix.S_IFMT == unix.S_IFCHR || st.Mode&unix.S_IFMT == unix.S_IFBLK {
		b.Printf("\t%d,%d", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
	} else {
		b.Printf("\t")
	}
	b.Printf("\t%d", st.Size)
	cfg.printTime(b, st.Atim.Sec)
	cfg.printTime(b, st.Mtim.Sec)
	cfg.printTime(b, st.Ctim.Sec)
}

func (cfg *filanConfig) printTime(b *outbuf.Buf, sec int64) {
	if cfg.rawOutput {
		b.Printf("\t%d", sec)
		return
	}
	t := time.Unix(sec, 0).Local()
	b.Printf("\t%s", t.Format("2006-01-02 15:04:05"))
}

// fileTypeString returns file/dir/symlink/chrdev/blkdev/pipe/socket/undef; test.sh greps these.
func fileTypeString(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "file"
	case unix.S_IFDIR:
		return "dir"
	case unix.S_IFLNK:
		return "symlink"
	case unix.S_IFCHR:
		return "chrdev"
	case unix.S_IFBLK:
		return "blkdev"
	case unix.S_IFIFO:
		return "pipe"
	case unix.S_IFSOCK:
		return "socket"
	default:
		return "undef"
	}
}

func printSocket(fd int, b *outbuf.Buf) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return
	}
	b.Printf("\t%s", sockAddrString(sa))
	// peer
	if pa, err := unix.Getpeername(fd); err == nil {
		b.Printf("\t%s", sockAddrString(pa))
	}
	// SO_TYPE
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err == nil {
		switch v {
		case unix.SOCK_STREAM:
			b.Print("\tSTREAM")
		case unix.SOCK_DGRAM:
			b.Print("\tDGRAM")
		case unix.SOCK_RAW:
			b.Print("\tRAW")
		case unix.SOCK_SEQPACKET:
			b.Print("\tSEQPACKET")
		default:
			b.Printf("\ttype=%d", v)
		}
	}
	// Socket options; test.sh LISTEN_KEEPALIVE greps KEEPALIVE=.
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_DEBUG, "DEBUG")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, "REUSEADDR")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_TYPE, "TYPE")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_ERROR, "ERROR")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_DONTROUTE, "DONTROUTE")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_BROADCAST, "BROADCAST")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_SNDBUF, "SNDBUF")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_RCVBUF, "RCVBUF")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, "KEEPALIVE")
	printSockoptInt(b, fd, unix.SOL_SOCKET, unix.SO_OOBINLINE, "OOBINLINE")
	printLinuxSockopts(b, fd)
	printSockoptInt(b, fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, "TCP_NODELAY")
	printSockoptInt(b, fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG, "TCP_MAXSEG")
	printSockoptInt(b, fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, "TCP_KEEPINTVL")
	printSockoptInt(b, fd, unix.IPPROTO_TCP, unix.TCP_KEEPCNT, "TCP_KEEPCNT")
}

func printSockoptInt(b *outbuf.Buf, fd, level, opt int, name string) {
	v, err := unix.GetsockoptInt(fd, level, opt)
	if err != nil {
		return
	}
	// TAB-separated NAME=value so test.sh sed can strip after KEEPALIVE=1.
	b.Printf("\t%s=%d", name, v)
}

func sockAddrString(sa unix.Sockaddr) string {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return fmt.Sprintf("%d.%d.%d.%d:%d", a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3], a.Port)
	case *unix.SockaddrInet6:
		return fmt.Sprintf("[%s]:%d", netIPv6(a.Addr), a.Port)
	case *unix.SockaddrUnix:
		name := a.Name
		if len(name) > 0 && name[0] == 0 {
			return "@" + name[1:]
		}
		return name
	default:
		return fmt.Sprintf("%T", sa)
	}
}

func netIPv6(b [16]byte) string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(b[0])<<8|uint16(b[1]),
		uint16(b[2])<<8|uint16(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]),
		uint16(b[8])<<8|uint16(b[9]),
		uint16(b[10])<<8|uint16(b[11]),
		uint16(b[12])<<8|uint16(b[13]),
		uint16(b[14])<<8|uint16(b[15]),
	)
}

func fdname(fd int, b *outbuf.Buf) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return
	}
	// -s prints "tcp"/"udp"/"unix"/… as the type, not generic "socket".
	// test.sh FILAN_SHORT_TCP greps the second field as "tcp".
	typ := fileTypeString(uint32(st.Mode))
	path := ""
	if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
		typ, path = shortSocketName(fd)
	} else if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
		path = p
	}
	// Skip Go runtime / systemd cgroup and epoll FDs after exec so EXEC_FDS /
	// EXEC_SNIFF still detect real socat leaks (extra sockets, -r/-R files).
	if fd >= 3 && isRuntimeNoisePath(path) {
		return
	}
	b.Printf("%5d %s %s\n", fd, typ, path)
}

// shortSocketName returns -s type ("tcp", "udp", "unix", …) and "local peer" address text for AF_INET/INET6/UNIX.
func shortSocketName(fd int) (typ, addrs string) {
	typ = "socket"
	proto, err := socketProtocol(fd)
	if err != nil {
		proto = -1
	}
	stype, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return typ, ""
	}
	local := sockAddrString(sa)
	peer := ""
	if pa, err := unix.Getpeername(fd); err == nil {
		peer = sockAddrString(pa)
	}
	listenTag := ""
	if v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err == nil && v != 0 {
		listenTag = "(listening)"
	}
	switch sa.(type) {
	case *unix.SockaddrInet4, *unix.SockaddrInet6:
		switch proto {
		case unix.IPPROTO_TCP:
			typ = "tcp" + listenTag
		case unix.IPPROTO_UDP:
			typ = "udp"
		case unix.IPPROTO_SCTP:
			typ = "sctp" + listenTag
		case unix.IPPROTO_RAW:
			typ = "raw"
		default:
			switch stype {
			case unix.SOCK_STREAM:
				typ = "tcp" + listenTag
			case unix.SOCK_DGRAM:
				typ = "udp"
			default:
				typ = fmt.Sprintf("proto%d", proto)
			}
		}
		if peer != "" {
			addrs = local + " " + peer
		} else {
			addrs = local
		}
	case *unix.SockaddrUnix:
		if stype == unix.SOCK_DGRAM {
			typ = "unixdatagram"
		} else {
			typ = "unix" + listenTag
		}
		addrs = local
	default:
		addrs = local
	}
	return typ, addrs
}

func isRuntimeNoisePath(path string) bool {
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "/sys/fs/cgroup/") {
		return true
	}
	if strings.HasPrefix(path, "anon_inode:") {
		return true
	}
	// Go internal notification / netpoll pipes sometimes show as pipe:[inode]
	// only when they are not stdio — leave pipe: visible if fd>=3 so real
	// leaks still show; only hide known runtime names.
	return false
}
