//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var handshakeProgress = []string{"timeout", "deadline", "expired", "handshake", "i/o timeout"}

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
	lower := bytes.ToLower(out)
	for _, want := range wantProgress {
		if want != "" && bytes.Contains(lower, bytes.ToLower([]byte(want))) {
			return nil
		}
	}
	return fmt.Errorf("accepted option failed without intended progress %v: %v: %s", wantProgress, err, out)
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
	if !bytes.Contains(out, []byte("address family")) && !bytes.Contains(out, []byte("bind")) {
		return fmt.Errorf("want family/bind error, got %s", out)
	}
	return nil
}

// legacyAcceptedOption is the old accepted-option oracle: any run that did
// not print "not supported" passed, including crashes and harness timeouts.
func legacyAcceptedOption(out []byte, _ error) bool {
	return !bytes.Contains(out, []byte("not supported"))
}

// legacyValidBind is the old valid-bind oracle: failures were ignored unless
// the output mentioned "address family".
func legacyValidBind(out []byte, err error) bool {
	if err != nil && !bytes.Contains(out, []byte("accept timeout")) && !bytes.Contains(bytes.ToLower(out), []byte("timeout")) {
		return !bytes.Contains(out, []byte("address family"))
	}
	return true
}

func TestLegacyAcceptedOptionAllowsCrashAndTimeout(t *testing.T) {
	crashOut, crashErr := []byte("panic: boom"), errors.New("exit status 2")
	if !legacyAcceptedOption(crashOut, crashErr) {
		t.Fatal("old accepted-option assertion should have ignored a crash")
	}
	if err := acceptedOptionResult(crashOut, crashErr, handshakeProgress); err == nil {
		t.Fatal("new accepted-option assertion must reject a crash")
	}

	timeoutOut, timeoutErr := []byte(""), context.DeadlineExceeded
	if !legacyAcceptedOption(timeoutOut, timeoutErr) {
		t.Fatal("old accepted-option assertion should have ignored a harness timeout")
	}
	if err := acceptedOptionResult(timeoutOut, timeoutErr, handshakeProgress); err == nil {
		t.Fatal("new accepted-option assertion must reject a harness timeout")
	}
}

func TestLegacyValidBindAllowsUnrelatedFailure(t *testing.T) {
	out, err := []byte("fatal: startup failed"), errors.New("exit status 2")
	if !legacyValidBind(out, err) {
		t.Fatal("old valid-bind assertion should have ignored an unrelated crash")
	}
	checkErr := invalidFamilyBindResult(out, err)
	if checkErr == nil {
		t.Fatal("new invalid-bind assertion must reject an unrelated crash")
	}
	if !strings.Contains(checkErr.Error(), "family/bind") {
		t.Fatalf("error=%v", checkErr)
	}
}

func TestRejectedOptionResultRejectsTimeout(t *testing.T) {
	err := rejectedOptionResult([]byte("not supported"), context.DeadlineExceeded, "not supported")
	if err == nil {
		t.Fatal("rejected-option assertion must fail on harness timeout")
	}
}
