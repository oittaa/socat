package sockopt_test

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio/sockopt"
)

func TestRejectUnsupportedIPAncillaryWithoutRegistration(t *testing.T) {
	spec, err := parse.ParseSpec("NOTAREAL:host,ip-pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	if err := sockopt.RejectUnsupportedIPAncillary(mustDecodeAddress(t, spec)); err != nil {
		t.Fatalf("unregistered type: %v", err)
	}
}
