//go:build linux || darwin

package xio

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	prepared, err := PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyConfiguredExecChildOptions(prepared.Config.Process, spec.Type, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/bin/echo" {
		t.Fatalf("Path=%q want /bin/echo (execvp token stays undashed)", cmd.Path)
	}
	if cmd.Args[0] != "-echo" {
		t.Fatalf("Args[0]=%q want -echo", cmd.Args[0])
	}
}

func TestApplySetpgidOmittedZeroOneNewGroup(t *testing.T) {
	for _, specText := range []string{"EXEC:true,setpgid", "EXEC:true,setpgid=0", "EXEC:true,setpgid=1", "EXEC:true,pgid"} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/true")
		prepared, err := PrepareSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyConfiguredExecChildOptions(prepared.Config.Process, spec.Type, cmd); err != nil {
			t.Fatal(err)
		}
		if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Pgid != 0 {
			t.Fatalf("%s SysProcAttr=%+v want Setpgid Pgid=0 (new process group)", specText, cmd.SysProcAttr)
		}
	}
}

func TestApplySetpgidOtherValueKeepsPgid(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:true,setpgid=4242")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/true")
	prepared, err := PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyConfiguredExecChildOptions(prepared.Config.Process, spec.Type, cmd); err != nil {
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
	_, err = PrepareSpec(spec)
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

func TestEXECDashWithHighFDOutRewritesTargetArgv0(t *testing.T) {
	bin := buildArgv0FDHelper(t)
	got := readExecStdout(t, "EXEC:"+bin+",dash,fdout=10")
	if got != "x-argv0fd" {
		t.Fatalf("dash argv0=%q want x-argv0fd", got)
	}
}

func TestEXECDashWithLowFDOutRewritesTargetArgv0(t *testing.T) {
	bin := buildArgv0Helper(t)
	got := strings.TrimSpace(captureInheritedStdout(t, func() {
		_ = openEXECSpec(t, "EXEC:"+bin+",dash,fdin=3,fdout=4", ModeRDWR)
	}))
	if got != "x-argv0" {
		t.Fatalf("dash argv0=%q want x-argv0 (wrapper must not steal dash)", got)
	}
}

func buildArgv0FDHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "argv0fd.c")
	body := "#include <stdio.h>\nint main(int argc, char **argv){ (void)argc; dprintf(10, \"x%s\\n\", argv[0] ? argv[0] : \"\"); return 0; }\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "argv0fd")
	out, err := exec.Command("gcc", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Skipf("gcc unavailable: %v (%s)", err, out)
	}
	return bin
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
	prepared, err := PrepareSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	peer := relay.FDStream{R: os.Stdin, W: os.Stdout, C: NopCloser{}}
	if err := runExecNoFork(context.Background(), peer, prepared.Config, nil, ModeRDWR); err != nil {
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
