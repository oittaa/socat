package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestRejectUnsupportedIPAncillaryWithoutRegistration(t *testing.T) {
	spec, err := parse.ParseSpec("NOTAREAL:host,ip-pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedIPAncillary(spec); err != nil {
		t.Fatalf("unregistered type: %v", err)
	}
}
