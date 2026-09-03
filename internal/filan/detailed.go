//go:build linux || darwin

// Package filan formats detailed file-descriptor reports.
package filan

import (
	"fmt"
	"math"
	"strconv"
	"time"
	"unicode"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

// Options controls detailed descriptor output.
type Options struct {
	Raw bool
}

// WriteHeader writes the detailed-report column header.
func WriteHeader(b *outbuf.Buf, opts Options) {
	b.Print("  FD  type\tdevice\tinode\tmode\tlinks\tuid\tgid\trdev\tsize\tblksize\tblocks")
	if opts.Raw {
		b.Print("\tatime\t\tmtime\t\tctime\t\tcloexec")
	} else {
		b.Print("\tatime\t\t\t\tmtime\t\t\t\tctime\t\t\t\tcloexec")
	}
	b.Print("\tflags\tsigown")
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
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFSOCK:
		printSocket(fd, b)
	case unix.S_IFIFO:
		printPipeSize(fd, b)
	case unix.S_IFCHR:
		printCharDev(fd, b, opts)
	}
	printPoll(fd, b, st.Mode&unix.S_IFMT == unix.S_IFSOCK)
	b.Println()
}

// WriteStat appends the stat columns for a descriptor or filesystem entry.
func WriteStat(b *outbuf.Buf, dynfd, statfd int, st *unix.Stat_t, opts Options) {
	fdshow := dynfd
	if fdshow < 0 {
		fdshow = statfd
	}
	dev, rdev := statDev(st)
	devStr := classicDevPair(dev)
	if opts.Raw {
		devStr = fmt.Sprintf("%d", st.Dev)
	}
	b.Printf("%4d: %s\t%s\t%d\t0%03o\t%d\t%d\t%d\t%s\t%d\t%d\t%d",
		fdshow,
		FileTypeString(uint32(st.Mode)),
		devStr,
		st.Ino,
		st.Mode,
		st.Nlink,
		st.Uid,
		st.Gid,
		classicDevPair(rdev),
		st.Size,
		st.Blksize,
		st.Blocks,
	)
	printTime(b, int64(st.Atim.Sec), opts.Raw)
	printTime(b, int64(st.Mtim.Sec), opts.Raw)
	printTime(b, int64(st.Ctim.Sec), opts.Raw)
}

func classicDevPair(dev uint64) string {
	return fmt.Sprintf("%d,%d", (dev>>8)&0xffff, dev&0xff)
}

func printTime(b *outbuf.Buf, sec int64, raw bool) {
	if raw {
		b.Printf("\t%d", sec)
		return
	}
	b.Printf("\t%s", time.Unix(sec, 0).Local().Format(time.DateTime+"-07:00"))
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

type dumpTermios struct {
	Iflag, Oflag, Cflag, Lflag uint64
	Cc                         []byte
}

func printCharDev(fd int, b *outbuf.Buf, opts Options) {
	t, err := getDumpTermios(fd)
	if err != nil {
		return
	}
	name := FDPath(fd)
	if name == "" {
		b.Print("\tNULL")
	} else {
		b.Printf("\t%s", name)
	}
	b.Printf(" \tIFLAGS=0x%06x OFLAGS=0x%06x CFLAGS=0x%06x LFLAGS=0x%06x",
		t.Iflag, t.Oflag, t.Cflag, t.Lflag)
	for i, ch := range t.Cc {
		b.Printf(" cc[%d]=%s", i, ccString(ch, opts.Raw))
	}
	if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil {
		b.Printf(" terminal window size:   %dx%d terminal window pixels: %dx%d",
			ws.Col, ws.Row, ws.Xpixel, ws.Ypixel)
	}
}

func ccString(ch byte, raw bool) string {
	if raw {
		return strconv.Itoa(int(ch))
	}
	if unicode.IsPrint(rune(ch)) && ch < 0x80 {
		return string(ch)
	}
	if ch < ' ' {
		return "^" + string(rune(ch+'@'))
	}
	return fmt.Sprintf("x%02X", ch)
}

func printPoll(fd int, b *outbuf.Buf, socket bool) {
	if fd < 0 || fd > math.MaxInt32 {
		return
	}
	pfd := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLIN | unix.POLLPRI | unix.POLLOUT,
	}}
	if _, err := unix.Poll(pfd, 0); err != nil {
		return
	}
	b.Print("\tpoll: ")
	re := pfd[0].Revents
	comma := false
	if re&unix.POLLIN != 0 {
		b.Print("IN")
		if n, err := fionread(fd); err == nil {
			b.Printf("(FIONREAD=%d)", n)
		}
		comma = true
	}
	if re&unix.POLLPRI != 0 {
		if comma {
			b.Print(",")
		}
		b.Print("PRI")
		comma = true
	}
	if re&unix.POLLOUT != 0 {
		if comma {
			b.Print(",")
		}
		b.Print("OUT")
		comma = true
	}
	if re&unix.POLLERR != 0 {
		if comma {
			b.Print(",")
		}
		b.Print("ERR")
		comma = true
	}
	if re&unix.POLLNVAL != 0 {
		if comma {
			b.Print(",")
		}
		b.Print("NVAL")
	}
	if re&unix.POLLIN != 0 && socket {
		printRecvmsgPeek(fd, b)
	}
}

func printRecvmsgPeek(fd int, b *outbuf.Buf) {
	b.Print("; ")
	var peek [1]byte
	oob := make([]byte, 5120)
	n, _, _, _, err := unix.Recvmsg(fd, peek[:], oob, unix.MSG_PEEK|unix.MSG_DONTWAIT)
	if err != nil {
		return
	}
	b.Printf("recvmsg=%d, ", n)
}
