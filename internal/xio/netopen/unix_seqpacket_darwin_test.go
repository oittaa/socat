//go:build darwin

package netopen

import (
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestUnixSeqpacketRejectedWhenUnsupported(t *testing.T) {
	spec, err := parse.ParseSpec("UNIX-CONNECT:/tmp/unused,so-type=" + strconv.Itoa(syscall.SOCK_SEQPACKET))
	if err != nil {
		t.Fatal(err)
	}
	_, err = tryAddr(spec)
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("error=%v want unsupported SOCK_SEQPACKET error", err)
	}
}
