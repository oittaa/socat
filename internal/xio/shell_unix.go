//go:build unix

package xio

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// Shell command assembly for EXEC/SYSTEM fdin=/fdout= redirection. The child
// is relaunched under /bin/sh so ExtraFiles (fd 3+) can be Dup2'd onto the
// classic fdi/fdo targets without leaving extra copies on stdin/stdout.

func rebuildWithSocketFDRedirect(
	ctx context.Context,
	cmd *exec.Cmd,
	mode Mode,
	fdin, fdout string,
	withStderr bool,
) *exec.Cmd {
	inSrc, outSrc := extraSources(mode, true)
	return rebuildWithShellPrefix(ctx, cmd, childFDRedirectPrefix(inSrc, outSrc, fdin, fdout, withStderr))
}

func rebuildWithPipeFDRedirect(
	ctx context.Context,
	cmd *exec.Cmd,
	mode Mode,
	fdin, fdout string,
	withStderr bool,
) *exec.Cmd {
	inSrc, outSrc := extraSources(mode, false)
	return rebuildWithShellPrefix(ctx, cmd, childFDRedirectPrefix(inSrc, outSrc, fdin, fdout, withStderr))
}

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

func rebuildWithShellPrefix(ctx context.Context, cmd *exec.Cmd, prefix string) *exec.Cmd {
	orig := ""
	if len(cmd.Args) > 0 {
		if cmd.Args[0] == "/bin/sh" || cmd.Args[0] == "sh" || strings.HasSuffix(cmd.Path, "/sh") {
			if len(cmd.Args) >= 3 && cmd.Args[1] == "-c" {
				orig = cmd.Args[2]
			}
		} else {
			orig = shellJoin(cmd.Args)
		}
	}
	return exec.CommandContext(ctx, "/bin/sh", "-c", prefix+"; "+orig) // #nosec G204 -- EXEC/SYSTEM runs the user command; prefix contains validated numeric FDs only
}

func shellJoin(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.ContainsAny(a, " \t'\"\\$`") {
			b.WriteByte('\'')
			b.WriteString(strings.ReplaceAll(a, "'", `'\''`))
			b.WriteByte('\'')
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}
