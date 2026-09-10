package testutil

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestUntilSucceedsOnProbe(t *testing.T) {
	var n atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := Until(ctx, func() (bool, error) {
		return n.Add(1) >= 2, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n.Load() < 2 {
		t.Fatalf("probes=%d", n.Load())
	}
}

func TestUntilReturnsProbeError(t *testing.T) {
	want := errors.New("probe")
	err := Until(context.Background(), func() (bool, error) {
		return false, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err=%v", err)
	}
}

func TestUntilHonorsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Until(ctx, func() (bool, error) { return false, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want canceled", err)
	}
}
