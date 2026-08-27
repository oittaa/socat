package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseTypeIntSockoptAllowsSignedValues(t *testing.T) {
	got, err := parseTypeIntSockopt(parse.Option{Name: "tcp-linger2", Value: "-1", Has: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != -1 {
		t.Fatalf("tcp-linger2=-1 parsed as %d", got)
	}
}

func TestParseTypeIntSockoptBareSCTPNodelayIsOne(t *testing.T) {
	// Classic xioopts.c TYPE_INT: no '=' stores 1. The man page shows
	// sctp-nodelay as a bare flag; that spelling must enable SCTP_NODELAY.
	got, err := parseTypeIntSockopt(parse.Option{Name: "sctp-nodelay"})
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("bare sctp-nodelay parsed as %d want 1", got)
	}
}
