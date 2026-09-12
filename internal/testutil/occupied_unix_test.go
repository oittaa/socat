//go:build linux || darwin

package testutil

import (
	"context"
	"net"
	"syscall"
	"testing"
)

func TestBindBusyIncludesAddrInUseAndAcces(t *testing.T) {
	for _, err := range []error{syscall.EADDRINUSE, syscall.EACCES} {
		if !BindBusy(err) {
			t.Fatalf("BindBusy(%v)=false", err)
		}
	}
}

func TestOccupiedReportsExistingTCPListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	occupied, err := Occupied(context.Background(), net.ListenConfig{}, "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !occupied {
		t.Fatal("listener was not reported occupied")
	}
}

func TestOccupiedReportsExistingUDPListener(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	occupied, err := Occupied(context.Background(), net.ListenConfig{}, "udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !occupied {
		t.Fatal("UDP listener was not reported occupied")
	}
}

func TestOccupiedFreePort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), PollInterval*50)
	defer cancel()
	err = Until(ctx, func() (bool, error) {
		occupied, err := Occupied(ctx, net.ListenConfig{}, "tcp4", addr)
		if err != nil {
			return false, err
		}
		return !occupied, nil
	})
	if err != nil {
		t.Fatalf("port %s still occupied after close: %v", addr, err)
	}
}
