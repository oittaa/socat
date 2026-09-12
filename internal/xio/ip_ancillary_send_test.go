package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestDecodeIPOptionsRejectsMalformedAndOversizedValues(t *testing.T) {
	for _, value := range []string{"x0", "x" + strings.Repeat("00", maxIPOptions+1)} {
		spec, err := parse.ParseSpec("TCP:127.0.0.1:9,ip-options=" + value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeAddress(spec); err == nil {
			t.Fatalf("ip-options=%q accepted", value)
		}
	}
}
