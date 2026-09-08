package fileopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseAcceptFDNumSharesParser(t *testing.T) {
	spec, err := parse.ParseSpec("ACCEPT-FD:0x20")
	if err != nil {
		t.Fatal(err)
	}
	n, err := parseFDNum(spec)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatalf("fd=%d want 32", n)
	}
}
