package testutil

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestListenOccupancyCancelIsNotBusy(t *testing.T) {
	occupied, err := listenOccupancy(context.Canceled)
	if occupied {
		t.Fatal("cancelled listen reported as occupied")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want canceled", err)
	}
}

func TestOccupiedInvalidAddressIsNotBusy(t *testing.T) {
	ctx := context.Background()
	occupied, err := Occupied(ctx, net.ListenConfig{}, "tcp", "not-a-host")
	if occupied {
		t.Fatal("invalid address reported as occupied")
	}
	if err == nil {
		t.Fatal("expected invalid address error")
	}
	if BindBusy(err) {
		t.Fatalf("invalid address classified as BindBusy: %v", err)
	}
}

func TestOccupiedUDPInvalidAddressIsNotBusy(t *testing.T) {
	occupied, err := Occupied(context.Background(), net.ListenConfig{}, "udp4", "not-a-host")
	if occupied || err == nil {
		t.Fatalf("occupied=%v err=%v want false and an error", occupied, err)
	}
	if BindBusy(err) {
		t.Fatalf("invalid UDP address classified as BindBusy: %v", err)
	}
}
