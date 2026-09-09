//go:build linux || darwin

package dtls13

import (
	"context"
	"os/exec"
	"testing"
)

func TestMatchDefaultResultRejectsPeerCrash(t *testing.T) {
	err := exec.Command("/bin/false").Run()
	if !processSelfExited(err) {
		t.Fatalf("processSelfExited(%v) = false", err)
	}
	r := defaultResult{stage: stageHandshake, err: context.DeadlineExceeded, waitErr: err}
	if matchDefaultResult(r, limitPionCID) == nil {
		t.Fatal("Pion CID accepted a peer that exited before handshake")
	}
	if matchDefaultResult(r, limitWolfSSLCH0) == nil {
		t.Fatal("wolfSSL CH0 accepted a peer that exited before handshake")
	}
}
