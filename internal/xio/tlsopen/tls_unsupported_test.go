package tlsopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestTLSConfigsRejectUnsupportedOpenSSLOptions(t *testing.T) {
	// Classic OPENSSL options that Go crypto/tls cannot honor. tag-1.8.1.3
	// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a is the same tree.
	cases := []struct {
		option string
		want   string
	}{
		{option: "openssl-method=DTLS1", want: "openssl-method"},
		{option: "opensslmethod=SSL3", want: "opensslmethod"},
		{option: "method=DTLS1.2", want: "method"},
		{option: "fips", want: "fips"},
		{option: "openssl-fips=1", want: "openssl-fips"},
		{option: "compress=none", want: "compress"},
		{option: "openssl-compress=zlib", want: "openssl-compress"},
		{option: "egd=/tmp/egd", want: "egd"},
		{option: "openssl-egd=/tmp/egd", want: "openssl-egd"},
		{option: "pseudo", want: "pseudo"},
		{option: "openssl-pseudo", want: "openssl-pseudo"},
		{option: "dh=dh.pem", want: "dh"},
		{option: "dhparam=dh.pem", want: "dhparam"},
		{option: "dhparams=dh.pem", want: "dhparams"},
		{option: "openssl-dhparam=dh.pem", want: "openssl-dhparam"},
		{option: "maxfraglen=512", want: "maxfraglen"},
		{option: "openssl-maxfraglen=512", want: "openssl-maxfraglen"},
		{option: "maxsendfrag=1024", want: "maxsendfrag"},
		{option: "openssl-maxsendfrag=1024", want: "openssl-maxsendfrag"},
	}
	for _, tc := range cases {
		t.Run("client/"+tc.option, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + tc.option)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tlsClientConfig(spec, "localhost")
			if err == nil {
				t.Fatal("expected unsupported OpenSSL option error")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
		t.Run("server/"+tc.option, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL-LISTEN:443," + tc.option)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tlsServerConfig(spec)
			if err == nil {
				t.Fatal("expected unsupported OpenSSL option error")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("unexpected error: %v", err)
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
