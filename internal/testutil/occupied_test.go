package testutil

import (
	"context"
	"errors"
	"net"
	"testing"
)

// legacyOccupied is the old e2e portOccupied rule: any listen error looked
// like occupancy, including cancel and invalid addresses.
func legacyOccupied(err error) (bool, error) {
	if err != nil {
		return true, nil
	}
	return false, nil
}

func TestListenOccupancyCancelIsNotBusy(t *testing.T) {
	occupied, err := listenOccupancy(context.Canceled)
	if occupied {
		t.Fatal("cancelled listen reported as occupied")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want canceled", err)
	}

	legacy, legacyErr := legacyOccupied(context.Canceled)
	if legacyErr != nil || !legacy {
		t.Fatalf("legacy occupied=%v err=%v; old portOccupied treated cancel as busy", legacy, legacyErr)
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

	legacy, legacyErr := legacyOccupied(err)
	if legacyErr != nil || !legacy {
		t.Fatalf("legacy occupied=%v err=%v; old portOccupied treated invalid addresses as busy", legacy, legacyErr)
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

func TestLegacyOccupiedTreatsAnyErrorAsBusy(t *testing.T) {
	cases := []error{context.Canceled, context.DeadlineExceeded, errors.New("permission denied")}
	for _, err := range cases {
		occupied, oerr := legacyOccupied(err)
		if oerr != nil || !occupied {
			t.Fatalf("legacy(%v)=(%v,%v) want occupied", err, occupied, oerr)
		}
		if BindBusy(err) {
			t.Fatalf("%v must stay an unexpected failure, not BindBusy", err)
		}
	}
}
