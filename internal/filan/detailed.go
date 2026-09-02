//go:build linux || darwin

// Package filan formats detailed file-descriptor reports.
package filan

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/oittaa/socat/internal/outbuf"
	"golang.org/x/sys/unix"
)

// Options controls detailed descriptor output.
type Options struct {
	Raw bool
}

// asctimeWidth is the padded timestamp column width so extra header tabs
// line up with cloexec when ISO-8601 times are used.
const asctimeWidth = 24

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
	printPoll(fd, b)
	b.Println()
}

// WriteStat appends the stat columns for a descriptor or filesystem entry.
func WriteStat(b *outbuf.Buf, dynfd, statfd int, st *unix.Stat_t, opts Options) {
	fdshow := dynfd
	if fdshow < 0 {
		fdshow = statfd
	}
	devStr := classicDevPair(uint64(st.Dev))
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
		classicDevPair(uint64(st.Rdev)),
		st.Size,
		st.Blksize,
		st.Blocks,
	)
	printTime(b, st.Atim.Sec, opts.Raw)
	printTime(b, st.Mtim.Sec, opts.Raw)
	printTime(b, st.Ctim.Sec, opts.Raw)
}

func classicDevPair(dev uint64) string {
	return fmt.Sprintf("%d,%d", uint16(dev>>8), uint16(dev&0xff)) // #nosec G115 -- print high/low 16 bits
}

func printTime(b *outbuf.Buf, sec int64, raw bool) {
	if raw {
		b.Printf("\t%d", sec)
		return
	}
	t := time.Unix(sec, 0).Local().Format(time.DateTime)
	if len(t) < asctimeWidth {
		t += strings.Repeat(" ", asctimeWidth-len(t))
	}
	b.Printf("\t%s", t)
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

func printCharDev(fd int, b *outbuf.Buf, opts Options) {
	t, err := unix.IoctlGetTermios(fd, termiosGet)
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
		uint32(t.Iflag), uint32(t.Oflag), uint32(t.Cflag), uint32(t.Lflag))
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

func printPoll(fd int, b *outbuf.Buf) {
	pfd := []unix.PollFd{{
		Fd:     int32(fd), // #nosec G115 -- pollfd.fd is C int
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
}
