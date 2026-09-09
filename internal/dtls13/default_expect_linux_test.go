//go:build linux || darwin

package dtls13

import (
	"context"
	"os/exec"
	"testing"
)

func TestMatchDefaultResultRejectsPeerCrash(t *testing.T) {
	err := exec.Command("/bin/false").Run()
	if !peerExitedOnItsOwn(err) {
		t.Fatalf("peerExitedOnItsOwn(%v) = false", err)
	}
	r := defaultResult{stage: stageHandshake, err: context.DeadlineExceeded, waitErr: err}
	if matchDefaultResult(r, limitPionCID) == nil {
		t.Fatal("Pion CID accepted a peer that exited before handshake")
	}
	if matchDefaultResult(r, limitWolfSSLCH0) == nil {
		t.Fatal("wolfSSL CH0 accepted a peer that exited before handshake")
	}
}

func TestMatchDefaultResultRejectsPeerSuccessExit(t *testing.T) {
	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Fatal(err)
	}
	r := defaultResult{stage: stageHandshake, err: context.DeadlineExceeded, waitErr: nil}
	if matchDefaultResult(r, limitWolfSSLCH0) == nil {
		t.Fatal("wolfSSL CH0 accepted /bin/true (exit 0, no listener)")
	}
	if matchDefaultResult(r, limitPionCID) == nil {
		t.Fatal("Pion CID accepted /bin/true")
	}
}

func TestMatchDefaultResultAcceptsHarnessKilledPeer(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	if peerExitedOnItsOwn(waitErr) {
		t.Fatalf("killed sleep treated as self-exit: %v", waitErr)
	}
	r := defaultResult{stage: stageHandshake, err: context.DeadlineExceeded, waitErr: waitErr}
	if err := matchDefaultResult(r, limitWolfSSLCH0); err != nil {
		t.Fatal(err)
	}
}
