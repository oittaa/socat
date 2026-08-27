//go:build unix

package xio

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func TestApplyDashArgv0RewritesBasename(t *testing.T) {
	cmd := exec.Command("/bin/echo", "x")
	spec, err := parse.ParseSpec("EXEC:/bin/echo,dash")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyExecChildOptions(spec, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/bin/echo" {
		t.Fatalf("Path=%q want /bin/echo (execvp token stays undashed)", cmd.Path)
	}
	if cmd.Args[0] != "-echo" {
		t.Fatalf("Args[0]=%q want -echo", cmd.Args[0])
	}
}

func TestApplyDashArgv0LoginAliasAndClear(t *testing.T) {
	on, err := parse.ParseSpec("EXEC:/bin/echo,login")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/echo")
	if err := applyExecChildOptions(on, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Args[0] != "-echo" {
		t.Fatalf("login Args[0]=%q want -echo", cmd.Args[0])
	}

	off, err := parse.ParseSpec("EXEC:/bin/echo,dash,dash=0")
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("/bin/echo")
	if err := applyExecChildOptions(off, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Args[0] != "/bin/echo" {
		t.Fatalf("dash then dash=0 Args[0]=%q want original", cmd.Args[0])
	}
}

func TestApplySetpgidBareAndZero(t *testing.T) {
	bare, err := parse.ParseSpec("EXEC:true,setpgid")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/true")
	if err := applyExecChildOptions(bare, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Pgid != 1 {
		t.Fatalf("bare setpgid SysProcAttr=%+v want Setpgid Pgid=1 (TYPE_INT default)", cmd.SysProcAttr)
	}

	zero, err := parse.ParseSpec("EXEC:true,pgid=0")
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("/bin/true")
	if err := applyExecChildOptions(zero, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Pgid != 0 {
		t.Fatalf("pgid=0 SysProcAttr=%+v want Setpgid Pgid=0", cmd.SysProcAttr)
	}
}

func TestApplySetpgidRejectsGarbage(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:true,setpgid=no")
	if err != nil {
		t.Fatal(err)
	}
	err = applyExecChildOptions(spec, exec.Command("/bin/true"))
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("error=%v want invalid setpgid", err)
	}
}

func TestEXECDashPrintsLoginArgv0(t *testing.T) {
	bin := buildArgv0Helper(t)
	got := readExecStdout(t, "EXEC:"+bin+",dash")
	if got != "x-argv0" {
		t.Fatalf("dash argv0=%q want x-argv0", got)
	}
	got = readExecStdout(t, "EXEC:"+bin+",login")
	if got != "x-argv0" {
		t.Fatalf("login argv0=%q want x-argv0", got)
	}
	got = readExecStdout(t, "EXEC:"+bin+",dash=0")
	if got != "x"+bin {
		t.Fatalf("dash=0 argv0=%q want x%s", got, bin)
	}
}

func buildArgv0Helper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "argv0.c")
	body := "#include <stdio.h>\nint main(int argc, char **argv){ (void)argc; printf(\"x%s\\n\", argv[0] ? argv[0] : \"\"); return 0; }\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "argv0")
	out, err := exec.Command("gcc", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Skipf("gcc unavailable: %v (%s)", err, out)
	}
	return bin
}

func TestSHELLLoginRewritesShellArgv0(t *testing.T) {
	got := readExecStdout(t, `SHELL:printf %s "x$0",shell=/bin/sh,login`)
	if got != "x-sh" {
		t.Fatalf("SHELL,login argv0=%q want x-sh", got)
	}
}

func TestSYSTEMDashRewritesShArgv0(t *testing.T) {
	got := readExecStdout(t, `SYSTEM:printf %s "x$0",dash`)
	if got != "x-sh" {
		t.Fatalf("SYSTEM,dash argv0=%q want x-sh", got)
	}
}

func TestEXECSetpgidZeroNewProcessGroup(t *testing.T) {
	parent := unix.Getpgrp()
	dir := t.TempDir()
	script := filepath.Join(dir, "showpgid")
	body := "#!/bin/sh\nprintf '%s %s\\n' \"$$\" \"$(ps -o pgid= -p $$ | tr -d '[:space:]')\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	got := readExecStdout(t, "EXEC:"+script+",setpgid=0")
	fields := strings.Fields(got)
	if len(fields) != 2 {
		t.Fatalf("child output %q want pid pgid", got)
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	pgid, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	if pgid != pid {
		t.Fatalf("child pgid=%d pid=%d want new process group", pgid, pid)
	}
	if unix.Getpgrp() != parent {
		t.Fatalf("parent pgid changed from %d to %d", parent, unix.Getpgrp())
	}
}

func TestEXECSetpgidDoesNotMutateParentOnNofork(t *testing.T) {
	parent := unix.Getpgrp()
	dir := t.TempDir()
	script := filepath.Join(dir, "ok")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec("EXEC:" + script + ",nofork,setpgid=0")
	if err != nil {
		t.Fatal(err)
	}
	peer := relay.FDStream{R: os.Stdin, W: os.Stdout, C: NopCloser{}}
	if err := runExecNoFork(context.Background(), peer, s, nil, ModeRDWR); err != nil {
		t.Fatal(err)
	}
	if unix.Getpgrp() != parent {
		t.Fatalf("nofork setpgid mutated parent pgid %d → %d", parent, unix.Getpgrp())
	}
}

func readExecStdout(t *testing.T, spec string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenChannel(ctx, ch, ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, o.Stream); err != nil {
		t.Fatal(err)
	}
	_ = o.Close()
	return strings.TrimSpace(buf.String())
}
