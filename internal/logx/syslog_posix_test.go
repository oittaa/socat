//go:build linux || darwin

package logx

import (
	"log/syslog"
	"testing"
)

func TestFacilityPriorityUsesPreparedFacility(t *testing.T) {
	if facilityPriority(FacilityLocal0) != syslog.LOG_LOCAL0 {
		t.Fatal("local0")
	}
	if facilityPriority(FacilityDaemon) != syslog.LOG_DAEMON {
		t.Fatal("daemon")
	}
	if facilityPriority(FacilityAuthpriv) != syslog.LOG_AUTHPRIV {
		t.Fatal("authpriv")
	}
}
