package dtls13

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

type defaultStage string

const (
	stageHandshake   defaultStage = "handshake"
	stageCertificate defaultStage = "certificate"
	stageApplication defaultStage = "application"
	stagePeerExit    defaultStage = "peer-exit"
)

type defaultLimit int

const (
	limitNone defaultLimit = iota
	limitPionCID
	limitPionMLDSA
	limitWolfSSLCH0
	limitWolfSSLMLDSA
)

type defaultResult struct {
	stage   defaultStage
	err     error
	waitErr error
	state   tls.ConnectionState
	output  string
}

// peerExitedOnItsOwn is true when the peer process finished on its own:
// exit 0 (Wait returns nil) or a normal exit status. Harness cancellation
// and Kill leave an ExitError whose process did not Exited() (Unix signal).
func peerExitedOnItsOwn(err error) bool {
	if err == nil {
		return true
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ProcessState == nil {
		return false
	}
	return ee.ProcessState.Exited()
}

func handshakeComplete(state tls.ConnectionState) bool {
	return state.CipherSuite != 0 && len(state.VerifiedChains) > 0
}

func matchDefaultResult(r defaultResult, limit defaultLimit) error {
	switch limit {
	case limitNone:
		if r.err != nil {
			return fmt.Errorf("unexpected failure at %s: %v\n%s", r.stage, r.err, r.output)
		}
		return nil
	case limitPionMLDSA:
		if r.err == nil {
			return fmt.Errorf("Pion accepted an ML-DSA certificate")
		}
		if !strings.Contains(r.output, "invalid private key type") {
			return fmt.Errorf("Pion ML-DSA failure at %s is not a cert-load error: %v\n%s", r.stage, r.err, r.output)
		}
		return nil
	case limitWolfSSLMLDSA:
		if r.err == nil {
			return fmt.Errorf("wolfSSL accepted an ML-DSA certificate")
		}
		if !strings.Contains(r.output, "can't load") {
			return fmt.Errorf("wolfSSL ML-DSA failure at %s is not a cert-load error: %v\n%s", r.stage, r.err, r.output)
		}
		return nil
	case limitWolfSSLCH0:
		if r.err == nil {
			return fmt.Errorf("wolfSSL accepted a fragmented first ClientHello")
		}
		if peerExitedOnItsOwn(r.waitErr) {
			return fmt.Errorf("wolfSSL peer exited before handshake (not CH0 timeout): %v\n%s", r.waitErr, r.output)
		}
		if r.stage != stageHandshake {
			return fmt.Errorf("wolfSSL CH0 expected a handshake failure, got %s: %v\n%s", r.stage, r.err, r.output)
		}
		if strings.Contains(r.output, "can't load") {
			return fmt.Errorf("wolfSSL cert-load failure, not CH0: %v\n%s", r.err, r.output)
		}
		if !errors.Is(r.err, context.DeadlineExceeded) {
			return fmt.Errorf("wolfSSL handshake failed without timeout (not CH0): %v\n%s", r.err, r.output)
		}
		return nil
	case limitPionCID:
		if r.err == nil {
			return nil
		}
		if !handshakeComplete(r.state) {
			return fmt.Errorf("Pion failed before handshake at %s: %v\n%s", r.stage, r.err, r.output)
		}
		if r.stage != stageApplication && r.stage != stagePeerExit {
			return fmt.Errorf("Pion CID expected after handshake, got %s: %v\n%s", r.stage, r.err, r.output)
		}
		if !strings.Contains(r.err.Error(), "unexpected message") {
			return fmt.Errorf("Pion handshake ok but failure is not CID unexpected message at %s: %v\n%s", r.stage, r.err, r.output)
		}
		return nil
	default:
		return fmt.Errorf("unknown default limit %d", limit)
	}
}

func TestMatchDefaultResult(t *testing.T) {
	handshake := tls.ConnectionState{Version: version13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, VerifiedChains: [][]*x509.Certificate{{}}}
	cidErr := errors.New("dtls: unexpected message")
	tests := []struct {
		name  string
		r     defaultResult
		limit defaultLimit
		ok    bool
	}{
		{name: "success", r: defaultResult{state: handshake}, limit: limitNone, ok: true},
		{name: "success-required-fails", r: defaultResult{stage: stageHandshake, err: context.DeadlineExceeded}, limit: limitNone},
		{name: "pion-cid-success", r: defaultResult{state: handshake}, limit: limitPionCID, ok: true},
		{name: "pion-cid-after-handshake", r: defaultResult{stage: stageApplication, err: cidErr, state: handshake, waitErr: errors.New("signal: killed")}, limit: limitPionCID, ok: true},
		{name: "pion-cid-peer-exit", r: defaultResult{stage: stagePeerExit, err: cidErr, state: handshake, waitErr: errors.New("signal: killed")}, limit: limitPionCID, ok: true},
		{name: "pion-cid-handshake-unexpected", r: defaultResult{stage: stageHandshake, err: cidErr, waitErr: errors.New("signal: killed")}, limit: limitPionCID},
		{name: "pion-cid-timeout-no-handshake", r: defaultResult{stage: stageHandshake, err: context.DeadlineExceeded}, limit: limitPionCID},
		{name: "pion-cid-wrong-error", r: defaultResult{stage: stageApplication, err: errors.New("read timeout"), state: handshake, waitErr: errors.New("signal: killed")}, limit: limitPionCID},
		{name: "pion-cid-exit-after-alert", r: defaultResult{stage: stageApplication, err: cidErr, state: handshake, waitErr: nil}, limit: limitPionCID, ok: true},
		{name: "pion-mldsa-load", r: defaultResult{stage: stageHandshake, err: context.DeadlineExceeded, output: "invalid private key type"}, limit: limitPionMLDSA, ok: true},
		{name: "pion-mldsa-timeout-only", r: defaultResult{stage: stageHandshake, err: context.DeadlineExceeded}, limit: limitPionMLDSA},
		{name: "wolfssl-mldsa-load", r: defaultResult{stage: stageHandshake, err: context.DeadlineExceeded, output: "can't load server cert file"}, limit: limitWolfSSLMLDSA, ok: true},
		{name: "wolfssl-ch0-timeout", r: defaultResult{stage: stageHandshake, err: context.DeadlineExceeded, waitErr: errors.New("signal: killed")}, limit: limitWolfSSLCH0, ok: true},
		{name: "wolfssl-ch0-true-exit", r: defaultResult{stage: stageHandshake, err: context.DeadlineExceeded}, limit: limitWolfSSLCH0},
		{name: "wolfssl-ch0-alert", r: defaultResult{stage: stageHandshake, err: cidErr, waitErr: errors.New("signal: killed")}, limit: limitWolfSSLCH0},
		{name: "wolfssl-ch0-application", r: defaultResult{stage: stageApplication, err: errors.New("echo"), waitErr: errors.New("signal: killed")}, limit: limitWolfSSLCH0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchDefaultResult(tt.r, tt.limit)
			if tt.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted an unrelated or incomplete failure")
			}
		})
	}
}
