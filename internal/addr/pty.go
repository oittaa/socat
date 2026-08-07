package addr

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/creack/pty"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// openPTY implements classic PTY address: allocate a pseudo-terminal, optionally
// create a symlink to the slave (link=), optionally put master in raw mode (cfmakeraw).
// The transfer stream is the master side; peers open the slave path via the link.
func openPTY(_ context.Context, s parse.Spec, _ Mode, g *Global) (*Opened, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, fmt.Errorf("PTY: %w", err)
	}
	// We only need the master FD; slave path is used via symlink.
	slaveName := slave.Name()
	_ = slave.Close()

	if g != nil && g.Log != nil {
		g.Log.Noticef("PTY is %s", slaveName)
	}

	if s.BoolOption("cfmakeraw") || s.HasOption("cfmakeraw") {
		if err := setRaw(int(master.Fd())); err != nil {
			master.Close()
			return nil, fmt.Errorf("PTY cfmakeraw: %w", err)
		}
	}

	link := s.OptionValue("link", "")
	if link == "" {
		link = s.OptionValue("symbolic-link", "")
	}
	if link != "" {
		_ = os.Remove(link)
		if err := os.Symlink(slaveName, link); err != nil {
			master.Close()
			return nil, fmt.Errorf("PTY link: %w", err)
		}
	}

	st := fileStream(master)
	st, err = wrapCommon(s, st)
	if err != nil {
		master.Close()
		if link != "" {
			_ = os.Remove(link)
		}
		return nil, err
	}
	o := &Opened{
		Stream: st,
		Label:  "PTY:" + slaveName,
	}
	if link != "" {
		// Unlink symlink on close (classic often leaves it; tests recreate each run).
		o.addCleanup(func() { _ = os.Remove(link) })
	}
	return o, nil
}

func setRaw(fd int) error {
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	// cfmakeraw equivalent
	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB
	termios.Cflag |= unix.CS8
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0
	return unix.IoctlSetTermios(fd, unix.TCSETS, termios)
}

// silence unused
var _ = syscall.TCGETS
