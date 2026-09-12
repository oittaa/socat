//go:build linux || darwin

package xio

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestRetryingPeerThenNoForkUsesPreparedPolicy(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}

	const marker = "retry-nofork-handoff"
	addr := reservedTCP4Addr(t)
	left := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=2,interval=0,connect-timeout=1", addr))
	policy := left.Single.Config.Common.Retry.Policy()
	if policy.MaxAttempts < 2 {
		t.Fatalf("fixture policy attempts=%d", policy.MaxAttempts)
	}
	gate := newDestGate(addr, policy.MaxAttempts-1)
	g := retrySessionWithLog(&retryFanout{gates: []*destGate{gate}})
	t.Cleanup(gate.close)

	right := prepareChannel(t, "SYSTEM:printf "+marker+",nofork")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- RunPrepared(ctx, left, right, g)
	}()

	peer := waitConn(t, ctx, gate.accepted, "retrying peer production TCP")
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(marker))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatalf("handoff read: %v", err)
	}
	if string(got) != marker {
		t.Fatalf("handoff %q want %q", got, marker)
	}
	if err := waitErr(t, finished, 2*time.Second, "nofork run"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := gate.openings.Load(); got < int64(policy.MaxAttempts) {
		t.Fatalf("retrying peer DialTCPAll openings=%d want >= %d", got, policy.MaxAttempts)
	}
	if gate.startErr != nil {
		t.Fatal(gate.startErr)
	}
	if g.Child.ExitCode != 0 {
		t.Fatalf("nofork Child.ExitCode=%d want 0", g.Child.ExitCode)
	}
}
