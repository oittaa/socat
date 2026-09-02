package logx

import (
	"strings"
	"testing"
)

func TestCanonicalFacilityDefaultAndNames(t *testing.T) {
	got, err := CanonicalFacility("")
	if err != nil || got != DefaultFacility {
		t.Fatalf("empty: %q %v", got, err)
	}
	got, err = CanonicalFacility("LOCAL0")
	if err != nil || got != "local0" {
		t.Fatalf("LOCAL0: %q %v", got, err)
	}
	if _, err := CanonicalFacility("not-a-facility"); err == nil || !strings.Contains(err.Error(), `unknown syslog facility "not-a-facility"`) {
		t.Fatalf("invalid: %v", err)
	}
}
