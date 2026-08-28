//go:build unix

package xio

import (
	"context"
	"os/exec"
	"strings"
)

// Shell command assembly for EXEC/SYSTEM fdin=/fdout= redirection. The child
// is relaunched under /bin/sh with exec N<&0 / N>&1 prepended, so the original
// argv must be re-quoted for shell parsing.

func rebuildWithFDRedirect(ctx context.Context, cmd *exec.Cmd, fdin, fdout string) *exec.Cmd {
	return rebuildWithShellPrefix(ctx, cmd, processFDRedirectPrefix(fdin, fdout))
}

// rebuildWithSocketFDRedirect maps a socket inherited as child fd 3 onto the
// descriptors classic selects with fdin/fdout. Directions not carried by the
// address mode remain inherited, as do standard descriptors replaced by a
// nonstandard fdi/fdo.
func rebuildWithSocketFDRedirect(
	ctx context.Context,
	cmd *exec.Cmd,
	mode Mode,
	fdin, fdout string,
	withStderr bool,
) *exec.Cmd {
	const socketFD = "3"
	redir := "exec"
	keepSocketFD := false
	outFD := fdout
	if outFD == "" {
		outFD = "1"
	}
	if mode != ModeRead {
		inFD := fdin
		if inFD == "" {
			inFD = "0"
		}
		redir += " " + inFD + "<&" + socketFD
		keepSocketFD = keepSocketFD || inFD == socketFD
	}
	if mode != ModeWrite {
		redir += " " + outFD + ">&" + socketFD
		keepSocketFD = keepSocketFD || outFD == socketFD
	}
	if withStderr {
		redir += " 2>&" + outFD
	}
	if !keepSocketFD {
		redir += " " + socketFD + ">&-"
	}
	return rebuildWithShellPrefix(ctx, cmd, redir)
}

func processFDRedirectPrefix(fdin, fdout string) string {
	redir := "exec"
	if fdin != "" {
		redir += " " + fdin + "<&0"
	}
	if fdout != "" {
		redir += " " + fdout + ">&1"
	}
	return redir
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
