//go:build darwin

package sockopt_test

import (
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestNonLinuxRejectsRouterAlertAtApply(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-router-alert")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: xio.DialControl(mustDecodeAddress(t, spec), "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("err=%v want not supported on this platform", err)
	}
}
