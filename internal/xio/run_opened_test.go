package xio

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestRunOpenedClosesLeftWhenRightPrepareFails(t *testing.T) {
	lo := &Opened{}
	closed := false
	lo.AddCleanup(func() { closed = true })
	ch, err := parse.ParseChannel("NOSUCH:x")
	if err != nil {
		t.Fatal(err)
	}
	err = RunOpened(context.Background(), lo, ch, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("error=%v", err)
	}
	if !closed {
		t.Fatal("left endpoint was not closed")
	}
}

func TestRunOpenedNilLeftOnPrepareFailure(t *testing.T) {
	ch, err := parse.ParseChannel("NOSUCH:x")
	if err != nil {
		t.Fatal(err)
	}
	err = RunOpened(context.Background(), nil, ch, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("error=%v", err)
	}
}
