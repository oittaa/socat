//go:build linux || darwin

package xio

import (
	"strconv"
)

// ExtraFiles sources and fdi/fdo numbering for EXEC/SYSTEM/SHELL.
// Runtime remapping is ExtraFiles plus the child dup2 helper
// (exec_fd_helper_unix.go), not a /bin/sh reconstruction, so bare SHELL
// keeps its argv and dash/login rewrite the target.

// extraSources returns ExtraFiles numbers for the child-side data descriptors.
// Socket/PTY share ExtraFiles[0] (fd 3) for both directions. Pipes use fd 3
// for the input pipe and fd 4 for the output pipe when both exist.
func extraSources(mode Mode, sameFD bool) (inSrc, outSrc string) {
	switch mode {
	case ModeRead:
		return "", "3"
	case ModeWrite:
		return "3", ""
	default:
		if sameFD {
			return "3", "3"
		}
		return "3", "4"
	}
}

func defaultFDI(fdin string) string {
	if fdin == "" {
		return "0"
	}
	return fdin
}

func defaultFDO(fdout string) string {
	if fdout == "" {
		return "1"
	}
	return fdout
}

func unusedFDNumbers(avoid ...string) (string, string) {
	taken := map[string]bool{"0": true, "1": true, "2": true}
	for _, a := range avoid {
		if a != "" {
			taken[a] = true
		}
	}
	found := make([]string, 0, 2)
	// Ubuntu /bin/sh is dash; its redirection grammar only accepts a
	// single-digit descriptor prefix (`10<&3` is a syntax error). Temps
	// stay in 3–9: the caller avoids at most two ExtraFiles sources and
	// two fdi/fdo targets, so two slots remain.
	for i := 3; i <= dashFDRedirectMax && len(found) < 2; i++ {
		s := strconv.Itoa(i)
		if !taken[s] {
			found = append(found, s)
		}
	}
	return found[0], found[1]
}
