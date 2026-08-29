//go:build unix && !linux

package xio

import (
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestNonLinuxRejectsRouterAlertAtApply(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("err=%v want not supported on this platform", err)
	}
}
