package proxyopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestParseHTTPVersionUnknown(t *testing.T) {
	s, err := parse.ParseSpec("PROXY:p:h:1,http-version=9")
	if err != nil {
		t.Fatal(err)
	}
	_, err = addrconfig.Decode(s, addrconfig.Facts{Type: "PROXY"})
	if err == nil || !strings.Contains(err.Error(), "http-version") {
		t.Fatalf("error=%v want http-version", err)
	}
}

func TestH2CRequiresVersion2(t *testing.T) {
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,h2c")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openProxyConnect(t.Context(), mustAddr(t, s), 0, nil)
	if err == nil {
		t.Fatal("expected h2c without http-version=2 to fail")
	}
}

func TestProxyStatusOK(t *testing.T) {
	if !proxyStatusOK("HTTP/1.0 200 OK\r\n") || !proxyStatusOK("HTTP/1.1   200\n") {
		t.Fatal("expected 200")
	}
	if proxyStatusOK("HTTP/1.0 403 Forbidden\r\n") || proxyStatusOK("HTTP/2 200\r\n") {
		t.Fatal("expected reject")
	}
}
