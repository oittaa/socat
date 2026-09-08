package tlsopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestTLSConfigsUseLastUnsupportedOpenSSLOptionValue(t *testing.T) {
	for _, options := range []string{
		"fips=0,fips",
		"pseudo=0,pseudo=1",
		"compress=none,compress=auto",
	} {
		t.Run(options, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + options)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tlsClientConfig(spec, "localhost")
			if err == nil || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("effective enabled option was not rejected: %v", err)
			}
		})
	}
}

func TestTLSConfigsRejectOpenSSLMethodValues(t *testing.T) {
	for _, optionName := range []string{"openssl-method", "opensslmethod", "method"} {
		for _, method := range []string{"SSL3", "SSL23", "DTLS1", "DTLS1.2"} {
			name := optionName + "=" + method
			t.Run("client/"+name, func(t *testing.T) {
				spec, err := parse.ParseSpec("OPENSSL:localhost:443," + name)
				if err != nil {
					t.Fatal(err)
				}
				_, err = tlsClientConfig(spec, "localhost")
				if err == nil {
					t.Fatal("expected unsupported method error")
				}
				if !strings.Contains(err.Error(), optionName) || !strings.Contains(err.Error(), "not supported") {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	}
}
