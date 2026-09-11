//go:build linux

package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestDialControlAppliesFreebind(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-freebind")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(mustDecodeAddress(t, spec), "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc := c.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_FREEBIND); got != 1 {
		t.Fatalf("IP_FREEBIND=%d want 1", got)
	}
}
