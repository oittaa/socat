//go:build unix

package xio

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

const execFDHelperTestTargetEnv = "SOCAT_TEST_EXEC_FD_HELPER_TARGET"

func runFDHelperRemapTest(
	t *testing.T,
	inTarget, outTarget int,
	targetMode string,
) (inputSource, outputSource string) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = inR.Close()
		_ = inW.Close()
		_ = outR.Close()
		_ = outW.Close()
	})

	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		execFDHelperMarker,
		"3", "4",
		strconv.Itoa(inTarget), strconv.Itoa(outTarget),
		"0",
		helper, helper, "-test.run=^TestExecFDHelperTarget$",
	}
	cmd := exec.Command(helper, args...)
	cmd.Env = append(withExecFDHelperEnv(nil), execFDHelperTestTargetEnv+"="+targetMode)
	cmd.ExtraFiles = []*os.File{inW, outW}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	_ = inW.Close()
	_ = outW.Close()
	if err != nil {
		t.Fatalf("fd helper: %v: stderr=%s", err, stderr.Bytes())
	}
	inData, err := io.ReadAll(inR)
	if err != nil {
		t.Fatal(err)
	}
	outData, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	return string(inData), string(outData)
}

func TestExecFDHelperRemapsSwappedSources(t *testing.T) {
	// ExtraFiles are input=3 and output=4. After swapping the targets,
	// writes to fd 4 must reach the input source and fd 3 the output source.
	in, out := runFDHelperRemapTest(t, 4, 3, "swap")
	if in != "I" || out != "O" {
		t.Fatalf("input source=%q output source=%q want I/O", in, out)
	}
}

func TestExecFDHelperSameTargetInputWins(t *testing.T) {
	// Classic's pipe path maps output first and input second. When the user
	// chooses one target for both, it therefore ends up on the input source.
	in, out := runFDHelperRemapTest(t, 10, 10, "same-target")
	if in != "X" || out != "" {
		t.Fatalf("input source=%q output source=%q want X/empty", in, out)
	}
}

// TestExecFDHelperTarget is re-executed through the real init-time helper.
// It writes directly to inherited descriptors so coverage does not depend on
// a shell accepting multi-digit redirection syntax.
func TestExecFDHelperTarget(t *testing.T) {
	mode := os.Getenv(execFDHelperTestTargetEnv)
	if mode == "" {
		t.Skip("exec fd helper target only")
	}
	if value := os.Getenv(execFDHelperEnv); value != "" {
		t.Fatalf("internal helper environment leaked to target: %q", value)
	}
	writeFD := func(fd int, data string) {
		t.Helper()
		f := os.NewFile(uintptr(fd), "exec-fd-helper-target")
		if f == nil {
			t.Fatalf("fd %d is unavailable", fd)
		}
		if _, err := f.Write([]byte(data)); err != nil {
			t.Fatalf("write fd %d: %v", fd, err)
		}
		_ = f.Close()
	}
	switch mode {
	case "swap":
		writeFD(4, "I")
		writeFD(3, "O")
	case "same-target":
		writeFD(10, "X")
	default:
		t.Fatalf("unknown helper target mode %q", mode)
	}
}

func TestRunExecFDHelperRejectsMalformedArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "too-short", args: nil, want: "invalid helper arguments"},
		{name: "descriptor", args: []string{"bad", "4", "5", "6", "0", "/bin/true", "true"}, want: "invalid descriptor"},
		{name: "stderr", args: []string{"3", "4", "5", "6", "2", "/bin/true", "true"}, want: "invalid stderr flag"},
		{name: "target", args: []string{"3", "4", "5", "6", "0", "", "true"}, want: "missing target command"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runExecFDHelper(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want substring %q", err, tc.want)
			}
		})
	}
}

func TestExecFDHelperEnvironmentHandshake(t *testing.T) {
	env := withExecFDHelperEnv([]string{"A=1", execFDHelperEnv + "=stale", "B=2"})
	count := 0
	for _, entry := range env {
		if entry == execFDHelperEnv+"=1" {
			count++
		}
		if entry == execFDHelperEnv+"=stale" {
			t.Fatalf("stale helper environment remained in %q", env)
		}
	}
	if count != 1 {
		t.Fatalf("helper environment count=%d in %q", count, env)
	}
	for _, entry := range withoutExecFDHelperEnv(env) {
		if strings.HasPrefix(entry, execFDHelperEnv+"=") {
			t.Fatalf("helper environment leaked in %q", env)
		}
	}
}
