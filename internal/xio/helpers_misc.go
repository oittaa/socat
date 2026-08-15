package xio

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

func unescapeShellQuotes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n == '"' || n == '\\' {
				b.WriteByte(n)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseDalanString parses a "..." string with escapes; returns payload and remainder.

func parseDalanString(s string) (out []byte, rest string, err error) {
	if len(s) == 0 || s[0] != '"' {
		return nil, s, fmt.Errorf("syntax error in %q", s)
	}
	i := 1
	for i < len(s) {
		c := s[i]
		if c == '"' {
			return out, s[i+1:], nil
		}
		if c == '\\' {
			i++
			if i >= len(s) {
				return nil, "", fmt.Errorf("syntax error in %q", s)
			}
			out = append(out, escapeByte(s[i]))
			i++
			continue
		}
		out = append(out, c)
		i++
	}
	return nil, "", fmt.Errorf("syntax error in %q", s)
}

// buildSockaddr builds unix.Sockaddr from domain + classic data (without family).

func escapeByte(c byte) byte {
	switch c {
	case '0':
		return 0
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'f':
		return '\f'
	case 'b':
		return '\b'
	case 'a':
		return '\a'
	case 'e':
		return 033
	case '\\':
		return '\\'
	case '"':
		return '"'
	case '\'':
		return '\''
	default:
		return c
	}
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
