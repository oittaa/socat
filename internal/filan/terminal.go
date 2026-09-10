//go:build linux || darwin

package filan

// IsTerminal reports whether fd answers a termios get.
func IsTerminal(fd int) bool {
	_, err := getDumpTermios(fd)
	return err == nil
}
