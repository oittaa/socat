package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

func TestRejectUnsupportedGetOnlyIPv4(t *testing.T) {
	for _, spec := range []string{
		"UDP4:127.0.0.1:1,ip-mtu",
		"UDP4:127.0.0.1:1,mtu=1",
		"TCP:127.0.0.1:1,ipmtu",
		"UDP4:127.0.0.1:1,ip-pktoptions",
		"UDP:127.0.0.1:1,pktopts",
		"TCP4:127.0.0.1:1,pktoptions=1",
		"UDP4:127.0.0.1:1,ippktoptions",
	} {
		s, err := parse.ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		err = RejectUnsupportedRemainingIPv4(mustDecodeAddress(t, s))
		if err == nil || !strings.Contains(err.Error(), "get-only") {
			t.Errorf("%s: err=%v want get-only", spec, err)
		}
	}
}

func TestGetOnlyIPv4DoesNotMatchMTUDiscover(t *testing.T) {
	s, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-mtu-discover=2")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedRemainingIPv4(mustDecodeAddress(t, s)); err != nil {
		t.Fatalf("ip-mtu-discover: %v", err)
	}
}

func TestRejectUnsupportedGetOnlyRecognizesSpellings(t *testing.T) {
	opts := []parse.Option{
		{Name: "ip-mtu"}, {Name: "ipmtu"}, {Name: "mtu"},
		{Name: "ip-pktoptions"}, {Name: "ippktoptions"}, {Name: "pktoptions"}, {Name: "pktopts"},
		{Name: "other", Spelling: " IP-MTU "},
	}
	for _, o := range opts {
		err := RejectUnsupportedRemainingIPv4(mustDecodeAddress(t, parse.Spec{Type: "TCP", Options: []parse.Option{o}}))
		if err == nil || !strings.Contains(err.Error(), "get-only") {
			t.Errorf("%+v: err=%v want get-only", o, err)
		}
	}
}

func decodeAddress(spec parse.Spec) (addrconfig.Address, error) {
	prepared, err := PrepareSpec(spec)
	if err == nil {
		return prepared.Config, nil
	}
	config, err2 := addrconfig.Decode(spec, addrconfig.Facts{Type: spec.Type})
	if err2 != nil {
		return addrconfig.Address{}, err
	}
	return config, nil
}

func mustDecodeAddress(t *testing.T, spec parse.Spec) addrconfig.Address {
	t.Helper()
	config, err := decodeAddress(spec)
	if err != nil {
		t.Fatal(err)
	}
	return config
}
