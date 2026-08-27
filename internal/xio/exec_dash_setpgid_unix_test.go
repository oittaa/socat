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

func TestApplySetpgidOmittedZeroOneNewGroup(t *testing.T) {
	for _, specText := range []string{"EXEC:true,setpgid", "EXEC:true,setpgid=0", "EXEC:true,setpgid=1", "EXEC:true,pgid"} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/true")
		if err := applyExecChildOptions(spec, cmd); err != nil {
			t.Fatal(err)
		}
		if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Pgid != 0 {
			t.Fatalf("%s SysProcAttr=%+v want Setpgid Pgid=0 (new process group)", specText, cmd.SysProcAttr)
		}
	}
}

func TestApplyDashRejectedOnSystemAndShell(t *testing.T) {
	for _, specText := range []string{
		"SYSTEM:true,dash",
		"SYSTEM:true,login",
		"SYSTEM:true,dash=0",
		`SHELL:printf x,login`,
		`SHELL:printf x,dash`,
	} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		err = applyExecChildOptions(spec, exec.Command("/bin/true"))
		if err == nil || !strings.Contains(err.Error(), "unused") || !strings.Contains(err.Error(), "classic EXEC only") {
			t.Fatalf("%s: error=%v want unused on SYSTEM/SHELL (classic EXEC only)", specText, err)
		}
		if spec.Type == "SYSTEM" && spec.HasOption("dash") && !strings.Contains(err.Error(), "SYSTEM") {
			t.Fatalf("%s: error=%v want address type SYSTEM", specText, err)
		}
		if spec.Type == "SHELL" && !strings.Contains(err.Error(), "SHELL") {
			t.Fatalf("%s: error=%v want address type SHELL", specText, err)
		}
	}
}

func TestApplySetpgidOtherValueKeepsPgid(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:true,setpgid=4242")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/true")
	if err := applyExecChildOptions(spec, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Pgid != 4242 {
		t.Fatalf("setpgid=4242 SysProcAttr=%+v want Pgid=4242", cmd.SysProcAttr)
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

func TestSYSTEMAndSHELLDashRejectedAtOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for _, specText := range []string{
		"SYSTEM:true,dash",
		"SYSTEM:true,login",
		`SHELL:printf x,shell=/bin/sh,login`,
	} {
		ch, err := parse.ParseChannel(specText)
		if err != nil {
			t.Fatalf("parse %s: %v", specText, err)
		}
		o, err := OpenChannel(ctx, ch, ModeRead, nil)
		if err == nil {
			_ = o.Close()
			t.Fatalf("%s: OpenChannel succeeded, want unused dash/login", specText)
		}
		if !strings.Contains(err.Error(), "unused") || !strings.Contains(err.Error(), "classic EXEC only") {
			t.Fatalf("%s: error=%v want unused (classic EXEC only)", specText, err)
		}
	}
}

func TestEXECSetpgidOmittedZeroOneNewProcessGroup(t *testing.T) {
	parent := unix.Getpgrp()
	bin := buildPgidHelper(t)
	for _, opt := range []string{"setpgid", "setpgid=0", "setpgid=1", "pgid"} {
		t.Run(opt, func(t *testing.T) {
			got := readExecStdout(t, "EXEC:"+bin+","+opt)
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
		})
	}
}

func buildPgidHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "pgid.c")
	body := "#include <stdio.h>\n#include <unistd.h>\nint main(void){ printf(\"%d %d\\n\", (int)getpid(), (int)getpgrp()); return 0; }\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "pgid")
	out, err := exec.Command("gcc", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Skipf("gcc unavailable: %v (%s)", err, out)
	}
	return bin
}

func TestEXECSetpgidDoesNotMutateParentOnNofork(t *testing.T) {
	parent := unix.Getpgrp()
	dir := t.TempDir()
	script := filepath.Join(dir, "ok")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec("EXEC:" + script + ",nofork,setpgid")
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
