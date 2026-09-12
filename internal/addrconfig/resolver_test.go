package addrconfig

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseResNSAddrRejectsIPv6(t *testing.T) {
	for _, input := range []string{"::1", "[::1]", "[::1]:53", "[2001:db8::1]:5353"} {
		_, err := ParseResNSAddr(input)
		if err == nil || !strings.Contains(err.Error(), "IPv6 nameserver is not supported") {
			t.Errorf("ParseResNSAddr(%q) err=%v want IPv6 nameserver is not supported", input, err)
		}
	}
}

func ExampleParseResNSAddr() {
	addr, _ := ParseResNSAddr("127.0.0.1:5353")
	fmt.Println(addr)
	// Output: 127.0.0.1:5353
}
