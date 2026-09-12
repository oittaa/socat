package testutil

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

// OutputDrainBound is the default time allowed for an output copy to finish
// after the child has exited or been killed.
const OutputDrainBound = time.Second

// Wait returns when done is closed. If ctx is done first, it calls stop so the
// caller can kill and reap the child, then waits for done. A completed child
// wins over a simultaneous cancel so success is not reported as a timeout.
func Wait(ctx context.Context, done <-chan struct{}, stop func()) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
	}
	select {
	case <-done:
		return nil
	default:
	}
	if stop != nil {
		stop()
	}
	<-done
	return ctx.Err()
}

// StartOutputPipe assigns an *os.File pipe to cmd.Stdout and, when Stderr is
// nil, to cmd.Stderr. The caller must close the write end after Start so the
// copy observes EOF. An existing Stderr (including a file used by signal
// tests) is left in place.
func StartOutputPipe(cmd *exec.Cmd, buf io.Writer) (pr, pw *os.File, copyDone <-chan error, err error) {
	if buf == nil {
		buf = io.Discard
	}
	pr, pw, err = os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd.Stdout = pw
	if cmd.Stderr == nil {
		cmd.Stderr = pw
	}
	done := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(buf, pr)
		done <- copyErr
	}()
	return pr, pw, done, nil
}

// DrainPipe waits for the output copy to finish. If it does not finish within
// bound, the read end is closed so the copy can unblock.
func DrainPipe(copyDone <-chan error, pr *os.File, bound time.Duration) error {
	if copyDone == nil {
		if pr != nil {
			_ = pr.Close()
		}
		return nil
	}
	if bound <= 0 {
		bound = OutputDrainBound
	}
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case err := <-copyDone:
		if pr != nil {
			_ = pr.Close()
		}
		return ignoreClosedCopy(err)
	case <-timer.C:
		if pr != nil {
			_ = pr.Close()
		}
		<-copyDone
		return context.DeadlineExceeded
	}
}

func ignoreClosedCopy(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
