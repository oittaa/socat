//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// handshakeTimeoutEvidence is application-timeout text from a clean exit, not
// the word "handshake" (present in stacks and WebSocket dial errors).
var handshakeTimeoutEvidence = []string{
	"deadline exceeded",
	"i/o timeout",
	"no recent network activity",
}

func harnessTimedOut(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func rejectedOptionResult(out []byte, err error, want string) error {
	if harnessTimedOut(err) {
		return fmt.Errorf("option rejection timed out: %w: %s", err, out)
	}
	if err == nil {
		return fmt.Errorf("expected error containing %q, got success: %s", want, out)
	}
	if ab := abnormalProcessOutcome(out, err); ab != nil {
		return ab
	}
	if !bytes.Contains(out, []byte(want)) {
		return fmt.Errorf("output=%q want substring %q", out, want)
	}
	return nil
}

func acceptedOptionResult(out []byte, err error, wantProgress []string) error {
	if harnessTimedOut(err) {
		return fmt.Errorf("accepted option timed out: %w: %s", err, out)
	}
	if bytes.Contains(out, []byte("not supported")) {
		return fmt.Errorf("unexpected option rejection: %s", out)
	}
	if err == nil {
		return fmt.Errorf("accepted handshake option succeeded against a silent peer: %s", out)
	}
	if ab := abnormalProcessOutcome(out, err); ab != nil {
		return ab
	}
	lower := bytes.ToLower(out)
	for _, want := range wantProgress {
		if want != "" && bytes.Contains(lower, bytes.ToLower([]byte(want))) {
			return nil
		}
	}
	return fmt.Errorf("accepted option failed without intended timeout %v: %v: %s", wantProgress, err, out)
}

func abnormalProcessOutcome(out []byte, err error) error {
	if err == nil {
		return nil
	}
	if bytes.Contains(out, []byte("panic:")) || bytes.Contains(bytes.ToLower(out), []byte("fatal error:")) {
		return fmt.Errorf("abnormal termination: %v: %s", err, out)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return fmt.Errorf("abnormal process outcome: %v: %s", err, out)
	}
	if ee.ExitCode() < 0 {
		return fmt.Errorf("abnormal termination (signal): %v: %s", err, out)
	}
	return nil
}

func acceptedConnectedResult(out []byte, err error, want []byte, srvStderr string) error {
	if harnessTimedOut(err) {
		return fmt.Errorf("accepted option timed out: %w: %s srv=%s", err, out, srvStderr)
	}
	if bytes.Contains(out, []byte("not supported")) {
		return fmt.Errorf("unexpected option rejection: %s srv=%s", out, srvStderr)
	}
	if err != nil {
		return fmt.Errorf("accepted option failed: %v: %s srv=%s", err, out, srvStderr)
	}
	if !bytes.Equal(out, want) {
		return fmt.Errorf("payload=%q want %q srv=%s", out, want, srvStderr)
	}
	return nil
}

func invalidFamilyBindResult(out []byte, err error) error {
	if harnessTimedOut(err) {
		return fmt.Errorf("invalid family bind timed out: %w: %s", err, out)
	}
	if err == nil {
		return fmt.Errorf("TCP4-LISTEN bind=:: succeeded: %s", out)
	}
	if ab := abnormalProcessOutcome(out, err); ab != nil {
		return ab
	}
	if !bytes.Contains(out, []byte("address family")) && !bytes.Contains(out, []byte("bind")) {
		return fmt.Errorf("want family/bind error, got %s", out)
	}
	return nil
}

func TestAcceptedOptionResultRejectsCrashAndTimeout(t *testing.T) {
	crashOut, crashErr := []byte("panic: boom"), errors.New("exit status 2")
	if err := acceptedOptionResult(crashOut, crashErr, handshakeTimeoutEvidence); err == nil {
		t.Fatal("accepted-option assertion must reject a crash")
	}

	timeoutOut, timeoutErr := []byte(""), context.DeadlineExceeded
	if err := acceptedOptionResult(timeoutOut, timeoutErr, handshakeTimeoutEvidence); err == nil {
		t.Fatal("accepted-option assertion must reject a harness timeout")
	}
}

func TestInvalidFamilyBindResultRejectsUnrelatedCrash(t *testing.T) {
	out, err := []byte("fatal: startup failed"), errors.New("exit status 2")
	checkErr := invalidFamilyBindResult(out, err)
	if checkErr == nil {
		t.Fatal("invalid-bind assertion must reject an unrelated crash")
	}
	if !strings.Contains(checkErr.Error(), "abnormal") {
		t.Fatalf("error=%v", checkErr)
	}
}

func TestRejectedOptionResultRejectsTimeout(t *testing.T) {
	err := rejectedOptionResult([]byte("not supported"), context.DeadlineExceeded, "not supported")
	if err == nil {
		t.Fatal("rejected-option assertion must fail on harness timeout")
	}
}

func TestAcceptedOptionResultRejectsHandshakeNamedCrash(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runTestCmd(ctx, e2eHelperCmd(ctx, "panic-handshake"))
	if err == nil {
		t.Fatal("expected crashing child to fail")
	}
	if harnessTimedOut(err) {
		t.Fatalf("crash looked like a harness timeout: %v %s", err, out)
	}
	if !bytes.Contains(out, []byte("handshake")) || !bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("crash output must be a panic that names handshake: %s", out)
	}
	if checkErr := acceptedOptionResult(out, err, handshakeTimeoutEvidence); checkErr == nil {
		t.Fatal("acceptedOptionResult must reject a handshake-named crash")
	}
}

func TestAcceptedOptionResultKeepsHarnessDeadlineDistinct(t *testing.T) {
	out := []byte("socat E context deadline exceeded")
	if err := acceptedOptionResult(out, context.DeadlineExceeded, handshakeTimeoutEvidence); err == nil {
		t.Fatal("harness deadline must not count as an application timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	appOut, appErr := runTestCmd(ctx, e2eHelperCmd(ctx, "exit-deadline"))
	if harnessTimedOut(appErr) {
		t.Fatalf("clean timeout exit looked like a harness deadline: %v %s", appErr, appOut)
	}
	if err := acceptedOptionResult(appOut, appErr, handshakeTimeoutEvidence); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidFamilyBindResultRejectsBindNamedCrash(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runTestCmd(ctx, e2eHelperCmd(ctx, "panic-bind"))
	if err == nil {
		t.Fatal("expected crashing child to fail")
	}
	if harnessTimedOut(err) {
		t.Fatalf("crash looked like a harness timeout: %v %s", err, out)
	}
	if !bytes.Contains(out, []byte("bind")) || !bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("crash output must be a panic that names bind: %s", out)
	}
	if checkErr := invalidFamilyBindResult(out, err); checkErr == nil {
		t.Fatal("invalidFamilyBindResult must reject a bind-named crash")
	}
}

func TestRejectedOptionResultRejectsPanicAfterDiagnostic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runTestCmd(ctx, e2eHelperCmd(ctx, "panic-after-reject"))
	if err == nil {
		t.Fatal("expected crashing child to fail")
	}
	if harnessTimedOut(err) {
		t.Fatalf("crash looked like a harness timeout: %v %s", err, out)
	}
	if !bytes.Contains(out, []byte("not supported")) || !bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("crash output must print the rejection diagnostic then panic: %s", out)
	}
	if checkErr := rejectedOptionResult(out, err, "not supported"); checkErr == nil {
		t.Fatal("rejectedOptionResult must reject a panic after the diagnostic")
	}
}

func TestRejectedOptionResultAcceptsCleanRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runTestCmd(ctx, e2eHelperCmd(ctx, "exit-not-supported"))
	if harnessTimedOut(err) {
		t.Fatalf("clean rejection looked like a harness deadline: %v %s", err, out)
	}
	if checkErr := rejectedOptionResult(out, err, "not supported"); checkErr != nil {
		t.Fatal(checkErr)
	}
}

func TestInvalidFamilyBindResultAcceptsCleanFamilyError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runTestCmd(ctx, e2eHelperCmd(ctx, "exit-address-family"))
	if harnessTimedOut(err) {
		t.Fatalf("clean family error looked like a harness deadline: %v %s", err, out)
	}
	if checkErr := invalidFamilyBindResult(out, err); checkErr != nil {
		t.Fatal(checkErr)
	}
}

func TestInvalidFamilyBindResultRejectsHarnessDeadline(t *testing.T) {
	err := invalidFamilyBindResult([]byte("address family"), context.DeadlineExceeded)
	if err == nil {
		t.Fatal("invalid-bind assertion must fail on harness timeout")
	}
}
