package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func mustSpec(t *testing.T, raw string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHasFDLifecycleOptionsCloexec(t *testing.T) {
	for _, raw := range []string{"FD:3,cloexec", "FD:3,cloexec=0", "TCP:localhost:1,cloexec=1", "OPEN:file,cloexec"} {
		if !hasFDLifecycleOptions(mustSpec(t, raw)) {
			t.Errorf("%s: cloexec must trigger ApplyFDOptions", raw)
		}
	}
}

func TestRequiredLifecycleOptionValueRejectsMissingValue(t *testing.T) {
	for _, raw := range []string{"FD:3,user", "FD:3,group", "FD:3,owner", "FD:3,gid"} {
		spec := mustSpec(t, raw)
		if _, err := requiredLifecycleOptionValue(spec.Options[0]); err == nil {
			t.Errorf("%s: missing value accepted", raw)
		}
	}
}

func TestLastLifecycleOptionModePermLastWins(t *testing.T) {
	o, ok := lastLifecycleOption(mustSpec(t, "FD:3,perm=0644,mode=0600"), "perm", "mode")
	if !ok || o.Value != "0600" {
		t.Fatalf("perm then mode: %+v ok=%v want 0600", o, ok)
	}
	o, ok = lastLifecycleOption(mustSpec(t, "FD:3,mode=0600,perm=0644"), "perm", "mode")
	if !ok || o.Value != "0644" {
		t.Fatalf("mode then perm: %+v ok=%v want 0644", o, ok)
	}
}

func TestLastLifecycleOptionUserUIDOwnerLastWins(t *testing.T) {
	o, ok := lastLifecycleOption(mustSpec(t, "FD:3,uid=1,owner=2,user=3"), "user", "uid", "owner")
	if !ok || o.Value != "3" {
		t.Fatalf("got %+v ok=%v want user=3", o, ok)
	}
	o, ok = lastLifecycleOption(mustSpec(t, "FD:3,user=3,uid=1"), "user", "uid", "owner")
	if !ok || o.Value != "1" {
		t.Fatalf("got %+v ok=%v want uid=1", o, ok)
	}
}
