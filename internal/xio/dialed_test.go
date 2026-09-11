package xio

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestOpenDialedCleanupOnDialError(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	_, err = OpenDialed(context.Background(), mustDecodeAddress(t, s), nil, Dialed{
		Dial:    func(context.Context) (net.Conn, error) { return nil, errors.New("dial failed") },
		Cleanup: []func(){func() { cleaned = true }},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !cleaned {
		t.Fatal("Cleanup not run")
	}
}
