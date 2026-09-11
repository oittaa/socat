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
		spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + options)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tlsClientConfig(mustAddr(t, spec), "localhost")
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%s: %v", options, err)
		}
	}
}

func TestTLSConfigsRejectOpenSSLMethodValues(t *testing.T) {
	for _, optionName := range []string{"openssl-method", "opensslmethod", "method"} {
		spec, err := parse.ParseSpec("OPENSSL:localhost:443," + optionName + "=DTLS1")
		if err != nil {
			t.Fatal(err)
		}
		_, err = tlsClientConfig(mustAddr(t, spec), "localhost")
		if err == nil || !strings.Contains(err.Error(), optionName) || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%s: %v", optionName, err)
		}
	}
}

func TestTLSClientRejectsHiddenFamilies(t *testing.T) {
	for _, opt := range []string{
		"method=TLS1", "fips", "egd=/tmp/egd", "pseudo",
		"dhparam=dh.pem", "maxfraglen=512", "maxsendfrag=1024",
	} {
		spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + opt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = TLSClientConfig(mustAddr(t, spec), "localhost")
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("%s: %v", opt, err)
		}
	}
}

func TestTLSServerRejectsFIPS(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPENSSL-LISTEN:443,verify=0,cert=" + cert + ",fips")
	if err != nil {
		t.Fatal(err)
	}
	_, err = TLSServerConfig(mustAddr(t, spec))
	if err == nil || !strings.Contains(err.Error(), `option "fips"`) {
		t.Fatalf("%v", err)
	}
}

func TestTLSDisabledFIPSAndCompressNone(t *testing.T) {
	for _, opt := range []string{"fips=0", "pseudo=0", "compress=none"} {
		spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0," + opt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := TLSClientConfig(mustAddr(t, spec), "localhost"); err != nil {
			t.Errorf("%s: %v", opt, err)
		}
	}
}

func TestTLSConfigsKeepEarlierUnsupportedAfterLaterDisable(t *testing.T) {
	spec, err := parse.ParseSpec("TLS:127.0.0.1:1,fips=1,pseudo=1,pseudo=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tlsClientConfig(mustAddr(t, spec), "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), `"fips"`) {
		t.Fatalf("fips must still be rejected: %v", err)
	}

	spec, err = parse.ParseSpec("TLS:127.0.0.1:1,method=SSLv23,fips=1,fips=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tlsClientConfig(mustAddr(t, spec), "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "method") || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("method must still be rejected: %v", err)
	}
}

func TestTLSFIPSAliasLastWins(t *testing.T) {
	spec, err := parse.ParseSpec("OPENSSL:localhost:443,verify=0,openssl-fips=1,fips=0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TLSClientConfig(mustAddr(t, spec), "localhost"); err != nil {
		t.Fatal(err)
	}
	spec, err = parse.ParseSpec("OPENSSL:localhost:443,verify=0,fips=0,openssl-fips=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TLSClientConfig(mustAddr(t, spec), "localhost"); err == nil {
		t.Fatal("enabled last value must reject")
	}
}
