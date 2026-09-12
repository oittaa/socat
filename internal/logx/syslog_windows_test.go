//go:build windows

package logx

import (
	"strings"
	"testing"
)

func TestDialSyslogRejectedOnWindows(t *testing.T) {
	_, err := DialSyslog("socat", FacilityDaemon)
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("err=%v", err)
	}
}
