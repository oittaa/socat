//go:build linux || darwin

// filan — file descriptor analyzer.
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

const (
	styleDetailed = 0
	styleSimple   = 's'
	styleLong     = 'S'
)

type filanConfig struct {
	followSymlinks bool
	rawOutput      bool
	style          int
	winch          bool
	m, n           int
	filename       string
	waittime       time.Duration
	outfname       string
	log            *logx.Logger
}

// winchTestHook, when set, replaces SIGWINCH so tests can reprint then stop.
var winchTestHook <-chan struct{}

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
			cfg.style = styleSimple
		case a == "-S":
			cfg.style = styleLong
		case a == "-r":
			cfg.rawOutput = true
		case a == "-W":
			cfg.winch = true
		case strings.HasPrefix(a, "-d"):
			if err := cfg.applyDebug(a, stderr); err != nil {
				if err := writeMsg(stderr, "filan: unknown option %q\n", a); err != nil {
					return 1
				}
				_ = usage(stderr)
				return 1
			}
		case strings.HasPrefix(a, "-i"):
			v, err := takeArg(a, "i", args, &i)
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			fd, err := parseBase0Int(v, "-i")
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			cfg.m, cfg.n = fd, fd
		case strings.HasPrefix(a, "-n"):
			v, err := takeArg(a, "n", args, &i)
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
					return 1
				}
				return 1
			}
			num, err := parseBase0Int(v, "-n")
			if err != nil {
				if err := writeMsg(stderr, "%v\n", err); err != nil {
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

	if err := cfg.analyzeOnce(out, stderr); err != nil {
		return 1
	}
	if !cfg.winch {
		return 0
	}
	return cfg.reprintOnWinch(out, stderr)
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

func parseBase0Int(v, what string) (int, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 0, 64)
	if err != nil || n > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("filan: bad %s %q", what, v)
	}
	return int(n), nil
}

func (cfg *filanConfig) applyDebug(a string, stderr io.Writer) error {
	rest := strings.TrimPrefix(a, "-d")
	if rest != "" && strings.Trim(rest, "d") != "" {
		return fmt.Errorf("unknown")
	}
	if cfg.log == nil {
		cfg.log = logx.New()
		cfg.log.SetProgname("filan")
		cfg.log.SetOutput(stderr)
	}
	n := 1 + len(rest)
	for i := 0; i < n; i++ {
		cfg.log.Increase()
	}
	return nil
}

func (cfg *filanConfig) debugf(format string, args ...any) {
	if cfg.log != nil {
		cfg.log.Debugf(format, args...)
	}
}

func (cfg *filanConfig) analyzeOnce(out, stderr io.Writer) error {
	var report outbuf.Buf
	if cfg.filename != "" {
		var err error
		if cfg.style == styleSimple || cfg.style == styleLong {
			err = cfg.fdnamePath(cfg.filename, &report)
		} else {
			err = cfg.filanFile(cfg.filename, &report)
		}
		if err != nil {
			if err := writeMsg(stderr, "filan: %v\n", err); err != nil {
				return err
			}
			return fmt.Errorf("filan file")
		}
		return report.Flush(out)
	}

	lo, hi := cfg.m, cfg.n
	one := lo == hi
	if one {
		// After parsing, m == n means analyze one descriptor (-i3, or -n0).
		hi = lo + 1
	}
	// Header line; test.sh LISTEN_KEEPALIVE skips it with tail -n +2.
	if cfg.style == styleDetailed {
		report.Println("  FD  typedeviceinodemodelinksuidgidrdevsizeblksizeblocksatimemtimectimecloexecflagssigownsigio")
	}
	for fd := lo; fd < hi; fd++ {
		if cfg.style == styleSimple || cfg.style == styleLong {
			cfg.fdname(fd, &report, !one)
		} else {
			cfg.filanFD(fd, &report)
		}
	}
	return report.Flush(out)
}

func (cfg *filanConfig) reprintOnWinch(out, stderr io.Writer) int {
	ch := winchTestHook
	if ch == nil {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, unix.SIGWINCH)
		defer signal.Stop(sigs)
		for range sigs {
			if err := cfg.analyzeOnce(out, stderr); err != nil {
				return 1
			}
		}
		return 0
	}
	for range ch {
		if err := cfg.analyzeOnce(out, stderr); err != nil {
			return 1
		}
	}
	return 0
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
		fd, err := parseBase0Int(name[1:], "-o")
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
	b.Println("  -d           increase verbosity (use up to 4 times)")
	b.Println("  -i<fdnum>    only analyze this fd")
	b.Println("  -n<fdnum>    analyze fds 0..fdnum-1")
	b.Println("  -s           simple output")
	b.Println("  -S           simple output with socket type and local-peer addresses")
	b.Println("  -f<filename> analyze filesystem entry")
	b.Println("  -T<seconds>  wait before analyzing")
	b.Println("  -r           raw time/rdev output")
	b.Println("  -L           follow symlinks")
	b.Println("  -W           reprint on SIGWINCH")
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
	cfg.debugf("checking file descriptor %d", fd)
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

func (cfg *filanConfig) fdnamePath(path string, b *outbuf.Buf) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return err
	}
	typ := fileTypeString(uint32(st.Mode))
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		typ = "link"
	}
	b.Printf("%s %s\n", typ, path)
	return nil
}

func (cfg *filanConfig) fdname(fd int, b *outbuf.Buf, numbered bool) {
	cfg.debugf("checking file descriptor %d", fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return
	}
	// -s prints "tcp"/"udp"/"unix"/… as the type, not generic "socket".
	// test.sh FILAN_SHORT_TCP greps the second field as "tcp".
	typ := fileTypeString(uint32(st.Mode))
	path := ""
	if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
		typ, path = shortSocketName(fd, cfg.style)
	} else if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
		path = p
	}
	// Skip Go runtime / systemd cgroup and epoll FDs after exec so EXEC_FDS /
	// EXEC_SNIFF still detect real socat leaks (extra sockets, -r/-R files).
	if fd >= 3 && isRuntimeNoisePath(path) {
		return
	}
	if numbered {
		b.Printf("%5d %s %s\n", fd, typ, path)
		return
	}
	b.Printf("%s %s\n", typ, path)
}

func socketTypeName(stype int) string {
	switch stype {
	case unix.SOCK_STREAM:
		return "stream"
	case unix.SOCK_DGRAM:
		return "dgram"
	case unix.SOCK_SEQPACKET:
		return "seqpacket"
	case unix.SOCK_RAW:
		return "raw"
	default:
		return fmt.Sprintf("socktype%d", stype)
	}
}

// shortSocketName returns -s/-S type ("tcp", "udp", "unix", …) and address text.
func shortSocketName(fd int, style int) (typ, addrs string) {
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
	var protoName string
	switch proto {
	case unix.IPPROTO_TCP:
		protoName = "tcp"
	case unix.IPPROTO_UDP:
		protoName = "udp"
	case unix.IPPROTO_SCTP:
		protoName = "sctp"
	case unix.IPPROTO_RAW:
		protoName = "raw"
	default:
		switch stype {
		case unix.SOCK_STREAM:
			protoName = "tcp"
		case unix.SOCK_DGRAM:
			protoName = "udp"
		default:
			protoName = fmt.Sprintf("proto%d", proto)
		}
	}
	switch sa.(type) {
	case *unix.SockaddrInet4:
		if style == styleLong {
			typ = protoName
			if peer == "" {
				peer = "0.0.0.0:0"
			}
			addrs = strings.TrimSpace(fmt.Sprintf("%s-%s (%s) %s", local, peer, socketTypeName(stype), listenTag))
		} else {
			typ = protoName + listenTag
			if peer != "" {
				addrs = local + " " + peer
			} else {
				addrs = local
			}
		}
	case *unix.SockaddrInet6:
		if style == styleLong {
			typ = protoName + "6"
			if peer == "" {
				peer = "[::]:0"
			}
			addrs = strings.TrimSpace(fmt.Sprintf("%s-%s (%s) %s", local, peer, socketTypeName(stype), listenTag))
		} else {
			typ = protoName + listenTag
			if peer != "" {
				addrs = local + " " + peer
			} else {
				addrs = local
			}
		}
	case *unix.SockaddrUnix:
		if style == styleLong {
			typ = "unix"
			addrs = strings.TrimSpace(fmt.Sprintf("%s-%s %s %s", local, peer, socketTypeName(stype), listenTag))
		} else {
			if stype == unix.SOCK_DGRAM {
				typ = "unixdatagram"
			} else {
				typ = "unix" + listenTag
			}
			addrs = local
		}
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
