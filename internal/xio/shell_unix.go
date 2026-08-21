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
	redir := "exec"
	if fdin != "" {
		redir += " " + fdin + "<&0"
	}
	if fdout != "" {
		redir += " " + fdout + ">&1"
	}
	return exec.CommandContext(ctx, "/bin/sh", "-c", redir+"; "+orig)
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
