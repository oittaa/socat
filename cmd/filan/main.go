// filan — file descriptor analyzer (classic socat companion).
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	followSymlinks bool
	rawOutput      bool
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var (
		m, n       = 0, unix.FD_SETSIZE
		style      = 0
		filename   string
		waittime   time.Duration
		outfname   string
		singleFD   = false
	)
	n = 1024 // practical default; FD_SETSIZE varies

	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "filan: unexpected argument %q\n", a)
			usage(os.Stderr)
			return 1
		}
		switch {
		case a == "-h" || a == "-?":
			usage(os.Stdout)
			return 0
		case a == "-L":
			followSymlinks = true
		case a == "-s":
			style = 1
		case a == "-r":
			rawOutput = true
		case a == "-d":
			// verbosity ignored for now
		case strings.HasPrefix(a, "-i"):
			v, err := takeArg(a, "i", args, &i)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fd, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "filan: bad -i %q\n", v)
				return 1
			}
			m, n = fd, fd
			singleFD = true
		case strings.HasPrefix(a, "-n"):
			v, err := takeArg(a, "n", args, &i)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			num, err := strconv.Atoi(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "filan: bad -n %q\n", v)
				return 1
			}
			n = num
		case strings.HasPrefix(a, "-f"):
			v, err := takeArg(a, "f", args, &i)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			filename = v
		case strings.HasPrefix(a, "-T"):
			v, err := takeArg(a, "T", args, &i)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			sec, err := strconv.ParseFloat(v, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "filan: bad -T %q\n", v)
				return 1
			}
			waittime = time.Duration(sec * float64(time.Second))
		case strings.HasPrefix(a, "-o"):
			v, err := takeArg(a, "o", args, &i)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			outfname = v
		default:
			fmt.Fprintf(os.Stderr, "filan: unknown option %q\n", a)
			usage(os.Stderr)
			return 1
		}
	}

	out := os.Stdout
	if outfname != "" {
		f, err := openOut(outfname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "filan: %v\n", err)
			return 1
		}
		if f != os.Stdout && f != os.Stderr && f != os.Stdin {
			defer f.Close()
		}
		out = f
	}

	if waittime > 0 {
		time.Sleep(waittime)
	}

	if filename != "" {
		if err := filanFile(filename, out); err != nil {
			fmt.Fprintf(os.Stderr, "filan: %v\n", err)
			return 1
		}
		return 0
	}

	if singleFD {
		n = m + 1
	}
	// Classic header line (LISTEN_KEEPALIVE uses tail -n +2 to skip it).
	if style != 1 {
		fmt.Fprintln(out, "  FD  typedeviceinodemodelinksuidgidrdevsizeblksizeblocksatimemtimectimecloexecflagssigownsigio")
	}
	for fd := m; fd < n; fd++ {
		if style == 1 {
			fdname(fd, out)
		} else {
			filanFD(fd, out)
		}
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
	return os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "filan by oittaa — analyze file descriptors (Go reimplementation of socat filan)")
	fmt.Fprintln(w, "Usage: filan [options]")
	fmt.Fprintln(w, "  -h|-?        help")
	fmt.Fprintln(w, "  -i<fdnum>    only analyze this fd")
	fmt.Fprintln(w, "  -n<fdnum>    analyze fds 0..fdnum-1")
	fmt.Fprintln(w, "  -s           simple output")
	fmt.Fprintln(w, "  -f<filename> analyze filesystem entry")
	fmt.Fprintln(w, "  -T<seconds>  wait before analyzing")
	fmt.Fprintln(w, "  -r           raw time/rdev output")
	fmt.Fprintln(w, "  -L           follow symlinks")
	fmt.Fprintln(w, "  -o<filename> output file")
}

func filanFile(path string, out io.Writer) error {
	var st unix.Stat_t
	var err error
	if followSymlinks {
		err = unix.Stat(path, &st)
	} else {
		err = unix.Lstat(path, &st)
	}
	if err != nil {
		return err
	}
	fd := -1
	// Symlinks and sockets: do not open (classic prints LINKTARGET for symlinks
	// when statfd < 0). Opening a socket path fails; opening a symlink would
	// follow it and lose the link type without -L.
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFSOCK, unix.S_IFLNK:
		// leave fd = -1
	default:
		f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
		if err == nil {
			fd = int(f.Fd())
			defer f.Close()
		}
	}
	printStat(-1, fd, &st, out)
	// Classic FILANSYMLINK: when analyzing a symlink path with lstat, append
	// LINKTARGET=... (no space before the keyword).
	if !followSymlinks && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		if target, err := os.Readlink(path); err == nil {
			fmt.Fprintf(out, "LINKTARGET=%s", target)
		}
	}
	fmt.Fprintln(out)
	return nil
}

func filanFD(fd int, out io.Writer) {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	if err != nil {
		return // skip closed FDs silently like classic often does for gaps
	}
	printStat(fd, fd, &st, out)

	// cloexec / flags
	cloexec, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	flags, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	fmt.Fprintf(out, "\t%d\tx%06x", cloexec, flags)
	if own, err := unix.FcntlInt(uintptr(fd), unix.F_GETOWN, 0); err == nil {
		fmt.Fprintf(out, "\t%d", own)
	}
	// socket extras
	if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
		printSocket(fd, out)
	}
	// try path from /proc
	if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
		fmt.Fprintf(out, "\t%s", p)
	}
	fmt.Fprintln(out)
}

func printStat(dynfd, statfd int, st *unix.Stat_t, out io.Writer) {
	fdshow := dynfd
	if fdshow < 0 {
		fdshow = statfd
	}
	devStr := fmt.Sprintf("%d,%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	if rawOutput {
		devStr = fmt.Sprintf("%d", st.Dev)
	}
	fmt.Fprintf(out, "%4d: %s\t%s\t%d\t%06o\t%d\t%d\t%d",
		fdshow,
		fileTypeString(st.Mode),
		devStr,
		st.Ino,
		st.Mode,
		st.Nlink,
		st.Uid,
		st.Gid,
	)
	if st.Mode&unix.S_IFMT == unix.S_IFCHR || st.Mode&unix.S_IFMT == unix.S_IFBLK {
		fmt.Fprintf(out, "\t%d,%d", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
	} else {
		fmt.Fprintf(out, "\t")
	}
	fmt.Fprintf(out, "\t%d", st.Size)
	printTime(out, st.Atim.Sec)
	printTime(out, st.Mtim.Sec)
	printTime(out, st.Ctim.Sec)
}

func printTime(out io.Writer, sec int64) {
	if rawOutput {
		fmt.Fprintf(out, "\t%d", sec)
		return
	}
	t := time.Unix(sec, 0).Local()
	fmt.Fprintf(out, "\t%s", t.Format("2006-01-02 15:04:05"))
}

// fileTypeString matches classic filan getfiletypestring() (test.sh greps these).
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

func printSocket(fd int, out io.Writer) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return
	}
	fmt.Fprintf(out, "\t%s", sockAddrString(sa))
	// peer
	if pa, err := unix.Getpeername(fd); err == nil {
		fmt.Fprintf(out, "\t%s", sockAddrString(pa))
	}
	// SO_TYPE
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err == nil {
		switch v {
		case unix.SOCK_STREAM:
			fmt.Fprint(out, "\tSTREAM")
		case unix.SOCK_DGRAM:
			fmt.Fprint(out, "\tDGRAM")
		case unix.SOCK_RAW:
			fmt.Fprint(out, "\tRAW")
		case unix.SOCK_SEQPACKET:
			fmt.Fprint(out, "\tSEQPACKET")
		default:
			fmt.Fprintf(out, "\ttype=%d", v)
		}
	}
	// Classic sockopts used by test.sh (LISTEN_KEEPALIVE greps KEEPALIVE=).
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_DEBUG, "DEBUG")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, "REUSEADDR")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_TYPE, "TYPE")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_ERROR, "ERROR")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_DONTROUTE, "DONTROUTE")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_BROADCAST, "BROADCAST")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_SNDBUF, "SNDBUF")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_RCVBUF, "RCVBUF")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, "KEEPALIVE")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_OOBINLINE, "OOBINLINE")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_NO_CHECK, "NO_CHECK")
	printSockoptInt(out, fd, unix.SOL_SOCKET, unix.SO_PRIORITY, "PRIORITY")
	printSockoptInt(out, fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, "TCP_NODELAY")
	printSockoptInt(out, fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG, "TCP_MAXSEG")
	printSockoptInt(out, fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, "TCP_KEEPIDLE")
	printSockoptInt(out, fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, "TCP_KEEPINTVL")
	printSockoptInt(out, fd, unix.IPPROTO_TCP, unix.TCP_KEEPCNT, "TCP_KEEPCNT")
}

func printSockoptInt(out io.Writer, fd, level, opt int, name string) {
	v, err := unix.GetsockoptInt(fd, level, opt)
	if err != nil {
		return
	}
	// Classic separates sockopts with TAB so test.sh sed can strip after KEEPALIVE=1.
	fmt.Fprintf(out, "\t%s=%d", name, v)
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

func fdname(fd int, out io.Writer) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return
	}
	typ := fileTypeString(st.Mode)
	path := ""
	if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
		path = p
	} else if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
		if sa, err := unix.Getsockname(fd); err == nil {
			path = sockAddrString(sa)
		}
	}
	// Go runtime / systemd often open cgroup and epoll FDs after exec. Classic
	// C filan has only 0/1/2 after a clean EXEC. Skip those so EXEC_FDS /
	// EXEC_SNIFF still detect real socat leaks (extra sockets, -r/-R files).
	if fd >= 3 && isRuntimeNoisePath(path) {
		return
	}
	fmt.Fprintf(out, "%5d %s %s\n", fd, typ, path)
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

