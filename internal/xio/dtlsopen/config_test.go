package dtlsopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestDTLSMethodAliasesRetainDTLS13Reason(t *testing.T) {
	for _, name := range []string{"openssl-method", "opensslmethod", "method"} {
		for _, server := range []bool{false, true} {
			role := "client"
			if server {
				role = "server"
			}
			t.Run(role+"/"+name, func(t *testing.T) {
				spec, err := parse.ParseSpec("DTLS:127.0.0.1:1,verify=0," + name + "=DTLS1.2")
				if err != nil {
					t.Fatal(err)
				}
				_, err = endpointConfig(spec, "127.0.0.1", server)
				if err == nil {
					t.Fatal("expected DTLS method rejection")
				}
				if !strings.Contains(err.Error(), "method selection is not supported; only DTLS 1.3 is available") {
					t.Fatalf("error=%v want DTLS 1.3 method reason", err)
				}
				if strings.Contains(err.Error(), "stream TLS only") {
					t.Fatalf("DTLS must not fall through to stream TLS reason: %v", err)
				}
			})
		}
	}
}
