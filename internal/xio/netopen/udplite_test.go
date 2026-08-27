package netopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestIpDgramProto(t *testing.T) {
	cases := []struct {
		typ  string
		want int
	}{
		{typ: "UDP", want: 0},
		{typ: "UDP4", want: 0},
		{typ: "UDP-LISTEN", want: 0},
		{typ: "UDP4-SENDTO", want: 0},
		{typ: "UDPLITE", want: ipprotoUDPLITE},
		{typ: "UDPLITE-CONNECT", want: ipprotoUDPLITE},
		{typ: "UDPLITE-L", want: ipprotoUDPLITE},
		{typ: "UDPLITE4", want: ipprotoUDPLITE},
		{typ: "UDPLITE4-LISTEN", want: ipprotoUDPLITE},
		{typ: "UDPLITE4-SEND", want: ipprotoUDPLITE},
		{typ: "UDPLITE4-DGRAM", want: ipprotoUDPLITE},
		{typ: "UDPLITE6-RECV", want: ipprotoUDPLITE},
		{typ: "UDPLITE6-RECVFROM", want: ipprotoUDPLITE},
	}
	for _, tc := range cases {
		if got := ipDgramProto(parse.Spec{Type: tc.typ}); got != tc.want {
			t.Errorf("ipDgramProto(%q)=%d want %d", tc.typ, got, tc.want)
		}
	}
}
