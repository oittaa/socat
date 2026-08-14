package proxyopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestParseHTTPVersion(t *testing.T) {
	cases := []struct {
		in   string
		want httpMajor
	}{
		{"PROXY:p:h:1", httpVer1},
		{"PROXY:p:h:1,http-version=1.0", httpVer1},
		{"PROXY:p:h:1,http-version=1.1", httpVer1},
		{"PROXY:p:h:1,http-version=1", httpVer1},
		{"PROXY:p:h:1,http-version=2", httpVer2},
		{"PROXY:p:h:1,http-version=2.0", httpVer2},
		{"PROXY:p:h:1,http-version=3", httpVer3},
		{"PROXY:p:h:1,http-version=3.0", httpVer3},
	}
	for _, tc := range cases {
		s, err := parse.ParseSpec(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseHTTPVersion(s)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %d want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseHTTPVersionUnknown(t *testing.T) {
	s, err := parse.ParseSpec("PROXY:p:h:1,http-version=9")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseHTTPVersion(s); err == nil {
		t.Fatal("expected error")
	}
}

func TestH2CRequiresVersion2(t *testing.T) {
	s, err := parse.ParseSpec("PROXY:127.0.0.1:127.0.0.1:9,h2c")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openProxyConnect(t.Context(), s, 0, nil)
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
