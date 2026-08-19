//go:build unix && !linux

package netopen

import (
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestUnixSeqpacketRejectedWhenUnsupported(t *testing.T) {
	_, _, err := unixSocketNetwork(parse.Spec{
		Type: "UNIX-CONNECT",
		Options: []parse.Option{{
			Name:  "socktype",
			Value: strconv.Itoa(syscall.SOCK_SEQPACKET),
			Has:   true,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("error=%v want unsupported SOCK_SEQPACKET error", err)
	}
}
