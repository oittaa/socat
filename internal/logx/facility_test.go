package logx

import (
	"strings"
	"testing"
)

func TestParseFacilityDefaultAndNames(t *testing.T) {
	got, err := ParseFacility("")
	if err != nil || got != FacilityDaemon {
		t.Fatalf("empty: %v %v", got, err)
	}
	got, err = ParseFacility("LOCAL0")
	if err != nil || got != FacilityLocal0 {
		t.Fatalf("LOCAL0: %v %v", got, err)
	}
	if _, err := ParseFacility("not-a-facility"); err == nil || !strings.Contains(err.Error(), `unknown syslog facility "not-a-facility"`) {
		t.Fatalf("invalid: %v", err)
	}
}
