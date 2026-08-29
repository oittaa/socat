//go:build e2e && (linux || darwin)

package e2e_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func runSocat(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	argv := append([]string{"-t", "1"}, args...)
	cmd := exec.CommandContext(ctx, socatBin(t), argv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

func TestEXECUnidirectionalCat(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat not available")
	}
	const payload = "hello"
	t.Run("exec-to-stdout", func(t *testing.T) {
		out, errb, err := runSocat(t, payload, "-u", "EXEC:/bin/cat", "STDOUT")
		if err != nil {
			t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
		}
		if out != payload {
			t.Fatalf("got %q want %q", out, payload)
		}
	})
	t.Run("stdin-to-exec", func(t *testing.T) {
		out, errb, err := runSocat(t, payload, "-u", "STDIN", "EXEC:/bin/cat")
		if err != nil {
			t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
		}
		if out != payload {
			t.Fatalf("got %q want %q", out, payload)
		}
	})
}

func TestEXECfdinFdoutInherit(t *testing.T) {
	tests := []struct {
		name string
		left string
	}{
		{name: "socketpair", left: "SYSTEM:printf O; printf D >&4,fdin=3,fdout=4"},
		{name: "pipes", left: "SYSTEM:printf O; printf D >&4,pipes,fdin=3,fdout=4"},
		{name: "pipes-overlap-fdin4-fdout5", left: "SYSTEM:printf O; printf D >&5,pipes,fdin=4,fdout=5"},
		{name: "pipes-overlap-swap-fdin4-fdout3", left: "SYSTEM:printf O; printf D >&3,pipes,fdin=4,fdout=3"},
		{name: "socketpair-high-fdout", left: "EXEC:/bin/bash -c \\\"printf O; printf D >&10\\\",fdin=9,fdout=10"},
		{name: "pipes-high-fdout", left: "EXEC:/bin/bash -c \\\"printf O; printf D >&10\\\",pipes,fdin=9,fdout=10"},
		{name: "pty", left: "SYSTEM:printf O; printf D >&4,pty,fdin=3,fdout=4,raw,echo=0"},
		{name: "pty-high-fdout", left: "EXEC:/bin/bash -c \\\"printf O; printf D >&10\\\",pty,fdin=9,fdout=10,raw,echo=0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := filepath.Join(t.TempDir(), "relayed")
			out, errb, err := runSocat(t, "", tc.left, "SYSTEM:cat >"+sink)
			if err != nil {
				t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
			}
			if out != "O" {
				t.Fatalf("inherited stdout %q want O", out)
			}
			data, err := os.ReadFile(sink)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(data); got != "D" {
				t.Fatalf("relayed %q want D", got)
			}
		})
	}
}

func TestEXECfdinOnlyWrite(t *testing.T) {
	out, errb, err := runSocat(t, "hello", "-u", "STDIN", "SYSTEM:cat <&3,fdin=3")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "hello" {
		t.Fatalf("got %q want hello", out)
	}
}

func TestEXECfdoutOnlyRead(t *testing.T) {
	out, errb, err := runSocat(t, "hello", "-u", "SYSTEM:cat >&4,fdout=4", "STDOUT")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "hello" {
		t.Fatalf("got %q want hello", out)
	}
}

func TestEXECStderrCustomFDOut(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "relayed")
	out, errb, err := runSocat(t, "", "SYSTEM:printf O; printf D >&4; printf E >&2,fdin=3,fdout=4,stderr", "SYSTEM:cat >"+sink)
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "O" {
		t.Fatalf("inherited stdout %q want O", out)
	}
	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "DE" {
		t.Fatalf("relayed %q want DE", got)
	}
}

func TestEXECChdirFDInFDOut(t *testing.T) {
	dir := t.TempDir()
	out, errb, err := runSocat(t, "", "SYSTEM:pwd,chdir="+dir+",fdin=3,fdout=4", "STDOUT")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	got := strings.TrimSpace(out)
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		want = dir
	}
	gotEval, err := filepath.EvalSymlinks(got)
	if err != nil {
		gotEval = got
	}
	if gotEval != want {
		t.Fatalf("pwd %q want %q (stderr=%s)", got, dir, errb)
	}
}

func TestEXECSocktypeDgram(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat not available")
	}
	out, errb, err := runSocat(t, "hello", "-u", "STDIN", "EXEC:/bin/cat,socktype="+strconv.Itoa(syscall.SOCK_DGRAM))
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "hello" {
		t.Fatalf("got %q want hello", out)
	}
}

func TestEXECfdinFdoutHighDescriptors(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not available")
	}
	const payload = "high-fd-payload"
	out, errb, err := runSocat(t, payload, "STDIO", "EXEC:/bin/bash -c \\\"cat <&9 >&10\\\",fdin=9,fdout=10")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != payload {
		t.Fatalf("got %q want %q", out, payload)
	}
}

func TestEXECNoForkfdinFdoutInherit(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "relayed")
	out, errb, err := runSocat(t, "", "SYSTEM:printf O; printf D >&4,nofork,fdin=3,fdout=4", "SYSTEM:cat >"+sink)
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "O" {
		t.Fatalf("inherited stdout %q want O", out)
	}
	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "D" {
		t.Fatalf("relayed %q want D", got)
	}
}

func TestEXECNoForkfdinOnlyWrite(t *testing.T) {
	out, errb, err := runSocat(t, "hello", "-u", "STDIN", "SYSTEM:cat <&3,nofork,fdin=3")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "hello" {
		t.Fatalf("got %q want hello", out)
	}
}

func TestEXECNoForkfdoutOnlyRead(t *testing.T) {
	out, errb, err := runSocat(t, "hello", "-u", "SYSTEM:cat >&4,nofork,fdout=4", "STDOUT")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "hello" {
		t.Fatalf("got %q want hello", out)
	}
}

func TestEXECNoForkStderrCustomFDOut(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "relayed")
	out, errb, err := runSocat(t, "", "SYSTEM:printf D >&4; printf E >&2,nofork,fdin=3,fdout=4,stderr", "SYSTEM:cat >"+sink)
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "DE" {
		t.Fatalf("relayed %q want DE (stdout=%q stderr=%s)", got, out, errb)
	}
}

func TestEXECNoForkfdinFdoutHighDescriptors(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash not available")
	}
	const payload = "high-fd-payload"
	out, errb, err := runSocat(t, payload, "STDIO", "EXEC:/bin/bash -c \\\"cat <&9 >&10\\\",nofork,fdin=9,fdout=10")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != payload {
		t.Fatalf("got %q want %q (stderr=%s)", out, payload, errb)
	}
}

func TestEXECExecFailureStatus(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "nofork-low", args: []string{"PIPE", "EXEC:/no/such/socat-exec-missing,nofork,fdin=3,fdout=4"}, want: 1},
		{name: "nofork-high", args: []string{"PIPE", "EXEC:/no/such/socat-exec-missing,nofork,fdin=10,fdout=11"}, want: 1},
		{name: "forked-low", args: []string{"PIPE", "EXEC:/no/such/socat-exec-missing,fdin=3,fdout=4"}, want: 1},
		{name: "system-nofork", args: []string{"PIPE", "SYSTEM:socat-exec-missing-cmd,nofork,fdin=3,fdout=4"}, want: 127},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, errb, err := runSocat(t, "", tc.args...)
			if err == nil {
				t.Fatalf("missing command succeeded stdout=%q stderr=%s", out, errb)
			}
			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("err=%v stderr=%s", err, errb)
			}
			if ee.ExitCode() != tc.want {
				t.Fatalf("exit=%d want %d stderr=%s", ee.ExitCode(), tc.want, errb)
			}
		})
	}
}

func TestEXECTargetExit127Preserved(t *testing.T) {
	for _, spec := range []string{
		"SYSTEM:exit 127,nofork,fdin=3,fdout=4",
		"SYSTEM:exit 127,fdin=3,fdout=4",
		"EXEC:/bin/sh -c \\\"exit 127\\\",nofork,fdin=3,fdout=4",
		"EXEC:/bin/sh -c \\\"exit 127\\\",fdin=3,fdout=4",
	} {
		t.Run(spec, func(t *testing.T) {
			out, errb, err := runSocat(t, "", "PIPE", spec)
			if err == nil {
				t.Fatalf("exit 127 succeeded stdout=%q stderr=%s", out, errb)
			}
			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("err=%v stderr=%s", err, errb)
			}
			if ee.ExitCode() != 127 {
				t.Fatalf("exit=%d want 127 stdout=%q stderr=%s", ee.ExitCode(), out, errb)
			}
		})
	}
}

func TestSHELLNoForkBareFDIn(t *testing.T) {
	out, errb, err := runSocat(t, "printf OK\nexit\n", "-u", "STDIN", "SHELL,nofork,fdin=3,shell=/bin/sh")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
	if out != "OK" {
		t.Fatalf("got %q want OK (stderr=%s)", out, errb)
	}
}

func TestEXECTrueNoForkCustomFDs(t *testing.T) {
	out, errb, err := runSocat(t, "", "PIPE", "EXEC:true,nofork,fdin=3,fdout=4")
	if err != nil {
		t.Fatalf("socat: %v: stderr=%s stdout=%q", err, errb, out)
	}
}
