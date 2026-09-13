package xio

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/relay"
)

func TestOpenDialedCleanupOrder(t *testing.T) {
	for _, failure := range []string{"dial", "wrap", "none"} {
		t.Run(failure, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer func() { _ = conn.Close() }()
			defer func() { _ = peer.Close() }()
			wantErr := errors.New(failure)
			order := ""
			opened, err := OpenDialed(t.Context(), decodeConnectBind(t, "TCP:127.0.0.1:1"), nil, Dialed{
				Dial: func(context.Context) (net.Conn, error) {
					if failure == "dial" {
						return nil, wantErr
					}
					return conn, nil
				},
				Wrap: func(c net.Conn) (relay.Stream, error) {
					if failure == "wrap" {
						return nil, wantErr
					}
					return relay.NetStream{Conn: c}, nil
				},
				Cleanup: []func(){func() { order += "A" }, func() { order += "B" }},
			})
			if failure != "none" && !errors.Is(err, wantErr) {
				t.Fatalf("error=%v", err)
			}
			if failure == "none" {
				if err != nil {
					t.Fatal(err)
				}
				if order != "" {
					t.Fatalf("cleaned up before Close: %q", order)
				}
				_ = opened.Close()
				_ = opened.Close()
			}
			if order != "BA" {
				t.Fatalf("cleanup order=%q, want BA exactly once", order)
			}
		})
	}
}
