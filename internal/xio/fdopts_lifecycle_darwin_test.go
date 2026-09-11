//go:build darwin

package xio

import (
	"errors"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func TestSetupStreamPermOnAnonymousSocketPropagatesFchmodError(t *testing.T) {
	cli, srv := localTCPPair(t)
	spec := mustSpec(t, "TCP:127.0.0.1:1,perm=0600")
	_, err := SetupStream(spec, relay.NetStream{Conn: cli})
	if err == nil {
		t.Fatal("expected fchmod error on anonymous socket descriptor")
	}
	if !strings.Contains(err.Error(), "fchmod") && !errors.Is(err, unix.EINVAL) {
		t.Fatalf("error=%v want fchmod EINVAL", err)
	}
	_ = srv
}
