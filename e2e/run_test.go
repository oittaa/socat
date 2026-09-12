//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

// runWithTimeout starts name/args under a context deadline, captures combined
// output through an *os.File pipe, waits on testProcess, and drains the copy
// with a bound. CommandContext owns cancellation; testProcess owns start,
// wait, and kill.
func runWithTimeout(t *testing.T, d time.Duration, name string, args ...string) ([]byte, error) {
	t.Helper()
	return runWithTimeoutInput(t, d, nil, name, args...)
}

func runWithTimeoutInput(t *testing.T, d time.Duration, stdin []byte, name string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return runTestCmd(ctx, cmd)
}

func runTestCmd(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	var buf lockedBuffer
	pr, pw, copyDone, err := testutil.StartOutputPipe(cmd, &buf)
	if err != nil {
		return nil, err
	}
	p, err := startTestProcess(cmd)
	_ = pw.Close()
	if err != nil {
		_ = pr.Close()
		<-copyDone
		return buf.Bytes(), err
	}
	waitErr := testutil.Wait(ctx, p.done, p.stop)
	if waitErr == nil {
		waitErr, _ = p.status()
	}
	if drainErr := testutil.DrainPipe(copyDone, pr, testutil.OutputDrainBound); waitErr == nil {
		waitErr = drainErr
	}
	return buf.Bytes(), waitErr
}
