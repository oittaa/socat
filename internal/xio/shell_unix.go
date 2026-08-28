//go:build unix

package xio

import (
	"strconv"
)

// ExtraFiles sources and classic fdi/fdo numbering for EXEC/SYSTEM/SHELL.
// Runtime remapping is ExtraFiles plus the child dup2 helper
// (exec_fd_helper_unix.go), not a /bin/sh reconstruction, so bare SHELL
// keeps its argv and dash/login rewrite the target. childFDRedirectPrefix
// documents the equivalent dash-safe shell grammar previously used for
// single-digit descriptors.

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

// childFDRedirectPrefix builds `exec` redirections matching classic
// xio-progcall.c Dup2 of the child data fd(s) onto fdi/fdo (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same). Unrelated 0/1/2
// stay inherited. Classic maps the output endpoint first and the input
// endpoint second, which matters for pipes when fdin == fdout: input wins.
// stderr is Dup2'd from the effective fdo when requested.
func childFDRedirectPrefix(inSrc, outSrc, fdin, fdout string, withStderr bool) string {
	var inT, outT string
	if inSrc != "" {
		inT = defaultFDI(fdin)
	}
	if outSrc != "" {
		outT = defaultFDO(fdout)
	}

	keep := map[string]bool{}
	if inT != "" {
		keep[inT] = true
	}
	if outT != "" {
		keep[outT] = true
	}

	origIn, origOut := inSrc, outSrc
	redir := "exec"

	if inSrc != "" && outSrc != "" && inSrc != outSrc &&
		((outT != "" && outT == inSrc) || (inT != "" && inT == outSrc)) {
		tmpIn, tmpOut := unusedFDNumbers(inSrc, outSrc, inT, outT)
		if inSrc != "" {
			redir += " " + tmpIn + "<&" + inSrc
			inSrc = tmpIn
		}
		if outSrc != "" {
			redir += " " + tmpOut + "<&" + outSrc
			outSrc = tmpOut
		}
	}

	if outT != "" && outSrc != "" && outT != outSrc {
		redir += " " + outT + ">&" + outSrc
	}
	if inT != "" && inSrc != "" && inT != inSrc {
		redir += " " + inT + "<&" + inSrc
	}
	if withStderr {
		if outT != "" {
			redir += " 2>&" + outT
		} else {
			redir += " 2>&1"
		}
	}

	for _, fd := range []string{origIn, origOut, inSrc, outSrc} {
		if fd == "" || keep[fd] {
			continue
		}
		redir += " " + fd + ">&-"
		keep[fd] = true
	}
	return redir
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
	// single-digit descriptor prefix (`10<&3` is a syntax error). Classic
	// dup2 takes an unsigned short. Temps stay in 3–9: the caller avoids at
	// most two ExtraFiles sources and two fdi/fdo targets, so two slots
	// remain (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
	// official master af5388c898c7bb60997935aee93c223deba60c4a is the same).
	for i := 3; i <= dashFDRedirectMax && len(found) < 2; i++ {
		s := strconv.Itoa(i)
		if !taken[s] {
			found = append(found, s)
		}
	}
	return found[0], found[1]
}
