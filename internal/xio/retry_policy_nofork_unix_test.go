//go:build linux || darwin

package xio

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestRetryingPeerThenNoForkUsesPreparedPolicy(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}

	const (
		leftSpec = "TCP:127.0.0.1:9,retry=2,interval=0"
		marker   = "retry-nofork-handoff"
	)
	wantAttempts := int64(decodeRetrySpec(t, leftSpec).Common.Retry.Policy().MaxAttempts)
	if wantAttempts < 2 {
		t.Fatalf("fixture policy attempts=%d", wantAttempts)
	}

	var attempts atomic.Int64
	peerCh := make(chan *os.File, 1)
	left := PreparedAddress{
		Config: decodeRetrySpec(t, leftSpec),
		opener: func(ctx context.Context, s addrconfig.Address, _ Mode, g *Global) (*Opened, error) {
			policy := fastRetryPolicy(s.Common.Retry.Policy())
			var opened *Opened
			err := WithRetry(ctx, g, policy, s.Type, func() error {
				n := attempts.Add(1)
				if policy.MaxAttempts != 0 && uint64(n) < policy.MaxAttempts {
					return errRetryAgain
				}
				a, b, err := unixSocketpairLogged(g)
				if err != nil {
					return err
				}
				o, err := NewReady("retry-peer", FileStream(a))
				if err != nil {
					_ = a.Close()
					_ = b.Close()
					return err
				}
				peerCh <- b
				opened = o
				return nil
			})
			return opened, err
		},
	}

	rightRaw, err := parse.ParseChannel("SYSTEM:printf " + marker + ",nofork")
	if err != nil {
		t.Fatal(err)
	}
	right, err := PrepareChannel(rightRaw)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	g := retrySession()
	if err := RunPrepared(ctx, PreparedChannel{Single: &left}, right, g); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := attempts.Load(); got != wantAttempts {
		t.Fatalf("retrying peer attempts=%d want %d", got, wantAttempts)
	}
	if g.Child.ExitCode != 0 {
		t.Fatalf("nofork Child.ExitCode=%d want 0", g.Child.ExitCode)
	}

	select {
	case peer := <-peerCh:
		t.Cleanup(func() { _ = peer.Close() })
		readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer readCancel()
		got := make(chan struct {
			b   []byte
			err error
		}, 1)
		go func() {
			buf := make([]byte, 64)
			n, err := peer.Read(buf)
			got <- struct {
				b   []byte
				err error
			}{buf[:n], err}
		}()
		select {
		case result := <-got:
			if result.err != nil {
				t.Fatalf("handoff read: %v", result.err)
			}
			if string(result.b) != marker {
				t.Fatalf("handoff %q want %q", result.b, marker)
			}
		case <-readCtx.Done():
			t.Fatal("handoff read timed out")
		}
	default:
		t.Fatal("retrying peer did not hand off a stream")
	}
}
