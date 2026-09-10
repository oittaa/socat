package tlsopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
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

func TestTLSClientAndServerRejectUnsupportedOpenSSLFamilies(t *testing.T) {
	cert := tlsListenCert(t)
	cases := []struct {
		option, spelling, reason string
	}{
		{"method=TLS1", "method", "stream TLS only"},
		{"opensslmethod=SSL3", "opensslmethod", "stream TLS only"},
		{"openssl-method=DTLS1", "openssl-method", "stream TLS only"},
		{"fips", "fips", "Go crypto/tls has no OpenSSL FIPS module"},
		{"openssl-fips=1", "openssl-fips", "Go crypto/tls has no OpenSSL FIPS module"},
		{"egd=/tmp/egd", "egd", "Go does not use EGD for randomness"},
		{"openssl-egd=/tmp/egd", "openssl-egd", "Go does not use EGD for randomness"},
		{"pseudo", "pseudo", "Go crypto/tls does not use OpenSSL pseudo-random bytes"},
		{"openssl-pseudo=1", "openssl-pseudo", "Go crypto/tls does not use OpenSSL pseudo-random bytes"},
		{"dh=dh.pem", "dh", "Go crypto/tls does not load DH parameters"},
		{"dhparam=dh.pem", "dhparam", "Go crypto/tls does not load DH parameters"},
		{"dhparams=dh.pem", "dhparams", "Go crypto/tls does not load DH parameters"},
		{"openssl-dhparam=dh.pem", "openssl-dhparam", "Go crypto/tls does not load DH parameters"},
		{"openssl-dhparams=dh.pem", "openssl-dhparams", "Go crypto/tls does not load DH parameters"},
		{"maxfraglen=512", "maxfraglen", "Go crypto/tls has no max fragment length option"},
		{"openssl-maxfraglen=512", "openssl-maxfraglen", "Go crypto/tls has no max fragment length option"},
		{"maxsendfrag=1024", "maxsendfrag", "Go crypto/tls has no max send fragment option"},
		{"openssl-maxsendfrag=-1", "openssl-maxsendfrag", "Go crypto/tls has no max send fragment option"},
	}
	for _, tc := range cases {
		t.Run("client/"+tc.option, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + tc.option)
			if err != nil {
				t.Fatal(err)
			}
			_, err = TLSClientConfig(spec, "localhost")
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), `option "`+tc.spelling+`"`) {
				t.Fatalf("error=%v want spelling %q", err, tc.spelling)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("error=%v want reason %q", err, tc.reason)
			}
		})
		t.Run("server/"+tc.option, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL-LISTEN:443,verify=0,cert=" + cert + "," + tc.option)
			if err != nil {
				t.Fatal(err)
			}
			_, err = TLSServerConfig(spec)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), `option "`+tc.spelling+`"`) {
				t.Fatalf("error=%v want spelling %q", err, tc.spelling)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("error=%v want reason %q", err, tc.reason)
			}
		})
	}
}

func TestTLSDisabledFIPSAndPseudoAreCompatible(t *testing.T) {
	cert := tlsListenCert(t)
	for _, option := range []string{"fips=0", "pseudo=0", "openssl-fips=0", "openssl-pseudo=0"} {
		t.Run("client/"+option, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + option)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := TLSClientConfig(spec, "localhost"); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("server/"+option, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL-LISTEN:443,verify=0,cert=" + cert + "," + option)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := TLSServerConfig(spec); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSUnsupportedAliasDuplicatesPreserveLastWins(t *testing.T) {
	cert := tlsListenCert(t)
	cases := []struct {
		options string
		reject  bool
	}{
		{"fips=0,openssl-fips=1", true},
		{"openssl-fips=1,fips=0", false},
		{"pseudo=1,openssl-pseudo=0", false},
		{"openssl-pseudo=0,pseudo", true},
		{"compress=none,compress=auto", true},
		{"compress=auto,compress=none", false},
		{"fips=false,fips=1", true},
		{"fips=1,fips=off", false},
	}
	for _, tc := range cases {
		t.Run("client/"+tc.options, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			_, err = TLSClientConfig(spec, "localhost")
			if tc.reject {
				if err == nil || !strings.Contains(err.Error(), "not supported") {
					t.Fatalf("error=%v want rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
		t.Run("server/"+tc.options, func(t *testing.T) {
			spec, err := parse.ParseSpec("OPENSSL-LISTEN:443,verify=0,cert=" + cert + "," + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			_, err = TLSServerConfig(spec)
			if tc.reject {
				if err == nil || !strings.Contains(err.Error(), "not supported") {
					t.Fatalf("error=%v want rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSCompressNoneRemainsCompatible(t *testing.T) {
	cert := tlsListenCert(t)
	client, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0,compress=none")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TLSClientConfig(client, "localhost"); err != nil {
		t.Fatal(err)
	}
	server, err := parse.ParseSpec("OPENSSL-LISTEN:443,verify=0,cert=" + cert + ",openssl-compress=none")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TLSServerConfig(server); err != nil {
		t.Fatal(err)
	}
}

func TestTLSRuntimeBoolFormsStayDistinctFromCLI(t *testing.T) {
	spec := parse.Spec{
		Type: "OPENSSL",
		Options: []parse.Option{
			{Name: "openssl-fips", Value: "false", Has: true},
		},
	}
	if _, err := TLSClientConfig(spec, "localhost"); err != nil {
		t.Fatalf("runtime Active() must accept fips=false: %v", err)
	}
}

func tlsListenCert(t *testing.T) string {
	t.Helper()
	path, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
