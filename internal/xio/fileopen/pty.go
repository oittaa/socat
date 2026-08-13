package fileopen

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// validateIntOption enforces classic integer option syntax for named options.
// Messages must contain "missing numerical value" / "trailing garbage" for test.sh.
func validateIntOption(s parse.Spec, name string) error {
	if !s.HasOption(name) {
		return nil
	}
	v := s.OptionValue(name, "")
	if v == "" {
		return fmt.Errorf("option \"%s\": missing numerical value", name)
	}
	// Reject leading non-digit (e.g. b19200)
	if !unicode.IsDigit(rune(v[0])) && v[0] != '-' && v[0] != '+' {
		return fmt.Errorf("option \"%s\": missing numerical value", name)
	}
	// Parse leading integer; trailing garbage is an error
	i := 0
	if v[0] == '+' || v[0] == '-' {
		i = 1
	}
	start := i
	for i < len(v) && unicode.IsDigit(rune(v[i])) {
		i++
	}
	if i == start {
		return fmt.Errorf("option \"%s\": missing numerical value", name)
	}
	if i < len(v) {
		return fmt.Errorf("option \"%s\": trailing garbage \"%s\"", name, v[i:])
	}
	if _, err := strconv.Atoi(v[:i]); err != nil {
		return fmt.Errorf("option \"%s\": missing numerical value", name)
	}
	_ = strings.TrimSpace
	return nil
}

// openPTY implements classic PTY address: allocate a pseudo-terminal, optionally
// create a symlink to the slave (link=), optionally put master in raw mode (cfmakeraw).
// The transfer stream is the master side; peers open the slave path via the link.
func openPTY(_ context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Classic rejects non-numeric ispeed/ospeed (tests MISSING_INTEGER / INTEGER_GARBAGE).
	if err := validateIntOption(s, "ispeed"); err != nil {
		return nil, err
	}
	if err := validateIntOption(s, "ospeed"); err != nil {
		return nil, err
	}
	// PTY takes no positional parameters (PTY::::: probes / PTY_VOIDARG).
	if len(s.Params) > 0 {
		return nil, fmt.Errorf("PTY: wrong number of parameters (expected 0)")
	}
	master, slave, err := xio.OpenPTYPair()
	if err != nil {
		return nil, fmt.Errorf("PTY: %w", err)
	}
	// Keep the slave open for the address lifetime. If the last slave FD is
	// closed, reads on the master return EIO and FAKEPTY-style servers exit
	// immediately (classic keeps a slave FD open while waiting for clients).
	slaveName := slave.Name()

	if g != nil && g.Log != nil {
		g.Log.Noticef("PTY is %s", slaveName)
	}

	if s.BoolOption("cfmakeraw") || s.HasOption("cfmakeraw") {
		if err := setRaw(int(master.Fd())); err != nil {
			master.Close()
			slave.Close()
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
			slave.Close()
			return nil, fmt.Errorf("PTY link: %w", err)
		}
	}
	// Classic perm=/user= on PTY applies to the slave node (stat -L follows link).
	_ = xio.ApplyPerm(slaveName, s, slave)
	_ = xio.ApplyOwner(slaveName, s, slave)
	if link != "" {
		_ = xio.ApplyPerm(link, s, nil)
	}

	// Use xio.PtyStream so half-close does not xio.Close the master (xio.FileStream would).
	st := xio.PtyStream(master)
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		master.Close()
		slave.Close()
		if link != "" {
			_ = os.Remove(link)
		}
		return nil, err
	}
	o := &xio.Opened{
		Stream: st,
		Label:  "PTY:" + slaveName,
	}
	o.AddCleanup(func() { _ = slave.Close() })
	if link != "" {
		// PTY_REMOVE: link gone when process exits (incl. SIGTERM).
		xio.RegisterUnlinkPath(link)
		o.AddCleanup(func() { _ = os.Remove(link) })
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
