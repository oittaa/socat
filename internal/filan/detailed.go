//go:build linux || darwin

// Package filan formats detailed file-descriptor reports.
package filan

import (
	"fmt"
	"os"
	"time"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

// Options controls detailed descriptor output.
type Options struct {
	Raw bool
}

// WriteHeader writes the detailed-report column header.
func WriteHeader(b *outbuf.Buf) {
	b.Print("  FD  type\tdevice\tinode\tmode\tlinks\tuid\tgid\trdev\tsize\tblksize\tblocks\tatime\tmtime\tctime\tcloexec\tflags\tsigown")
	appendSigioHeader(b)
	b.Println()
}

// WriteFD appends a detailed report for fd. Closed descriptors are skipped.
func WriteFD(b *outbuf.Buf, fd int, opts Options) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return
	}
	WriteStat(b, fd, fd, &st, opts)

	cloexec, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	flags, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	own, _ := unix.FcntlInt(uintptr(fd), unix.F_GETOWN, 0)
	b.Printf("\t%d\tx%06x\t%d", cloexec, flags, own)
	appendSigio(b, fd)
	if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
		printSocket(fd, b)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFIFO {
		printPipeSize(fd, b)
	}
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

// WriteStat appends the stat columns for a descriptor or filesystem entry.
func WriteStat(b *outbuf.Buf, dynfd, statfd int, st *unix.Stat_t, opts Options) {
	fdshow := dynfd
	if fdshow < 0 {
		fdshow = statfd
	}
	devStr := fmt.Sprintf("%d,%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	if opts.Raw {
		devStr = fmt.Sprintf("%d", st.Dev)
	}
	b.Printf("%4d: %s\t%s\t%d\t%06o\t%d\t%d\t%d",
		fdshow,
		FileTypeString(uint32(st.Mode)),
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
	b.Printf("\t%d", st.Blksize)
	b.Printf("\t%d", st.Blocks)
	printTime(b, st.Atim.Sec, opts.Raw)
	printTime(b, st.Mtim.Sec, opts.Raw)
	printTime(b, st.Ctim.Sec, opts.Raw)
}

func printTime(b *outbuf.Buf, sec int64, raw bool) {
	if raw {
		b.Printf("\t%d", sec)
		return
	}
	t := time.Unix(sec, 0).Local()
	b.Printf("\t%s", t.Format("2006-01-02 15:04:05"))
}

// FileTypeString returns file/dir/symlink/chrdev/blkdev/pipe/socket/undef.
func FileTypeString(mode uint32) string {
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
	b.Printf("\t%s", SockAddrString(sa))
	if pa, err := unix.Getpeername(fd); err == nil {
		b.Printf("\t%s", SockAddrString(pa))
	}
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
	b.Printf("\t%s=%d", name, v)
}

// SockAddrString formats a kernel sockaddr for filan output.
func SockAddrString(sa unix.Sockaddr) string {
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
