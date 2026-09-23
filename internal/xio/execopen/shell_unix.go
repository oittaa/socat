//go:build linux || darwin

package execopen

import "github.com/oittaa/socat/internal/xio"

// ExtraFiles sources and fdi/fdo numbering for EXEC/SYSTEM/SHELL.
// Runtime remapping is ExtraFiles plus the child dup2 helper
// (exec_fd_helper_unix.go), not a /bin/sh reconstruction, so bare SHELL
// keeps its argv and dash/login rewrite the target.

// extraSources returns ExtraFiles numbers for the child-side data descriptors.
// Socket/PTY share ExtraFiles[0] (fd 3) for both directions. Pipes use fd 3
// for the input pipe and fd 4 for the output pipe when both exist.
func extraSources(mode xio.Mode, sameFD bool) (inSrc, outSrc string) {
	switch mode {
	case xio.ModeRead:
		return "", "3"
	case xio.ModeWrite:
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
