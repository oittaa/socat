package addrconfig

import "testing"

func TestOptionValueErrorUsesTypedSpelling(t *testing.T) {
	spec := mustParseSpec(t, "TCP:host:9,so-rcvbuf=x")
	_, err := Decode(spec, tcpConnect)
	if err == nil || err.Error() != `TCP: option "so-rcvbuf": invalid value: "x"` {
		t.Fatalf("error=%v", err)
	}
}
