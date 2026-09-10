package dtlsopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestDTLSMethodAliasKeepsDTLS13Reason(t *testing.T) {
	spec, err := parse.ParseSpec("DTLS:127.0.0.1:1,opensslmethod=DTLS1.2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = endpointConfig(spec, "127.0.0.1", false)
	if err == nil || !strings.Contains(err.Error(), "only DTLS 1.3 is available") {
		t.Fatalf("%v", err)
	}
}
