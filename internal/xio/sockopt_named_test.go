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
