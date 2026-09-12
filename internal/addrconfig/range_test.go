package addrconfig

import (
	"strings"
	"testing"
)

func TestParseIPRangeKeepsHostnameUnresolvable(t *testing.T) {
	parsed, err := ParseIPRange("localhost:255.255.255.255")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Form != RangeAddrMask || parsed.Host.IsLiteral() || parsed.Host.Name != "localhost" {
		t.Fatalf("parsed=%+v", parsed)
	}

	cidr, err := ParseIPRange("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if cidr.Form != RangeCIDR || cidr.Prefix.String() != "127.0.0.0/8" {
		t.Fatalf("cidr=%+v", cidr)
	}

	_, err = ParseIPRange("X0000X7f000000:X0000xff000000")
	if err == nil || !strings.Contains(err.Error(), "invalid hex") {
		t.Fatalf("uppercase hex err=%v want invalid hex", err)
	}
}
