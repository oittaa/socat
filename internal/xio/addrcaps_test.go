package xio

import (
	"reflect"
	"testing"
)

func TestDerivedOptionCaps(t *testing.T) {
	cases := []struct {
		name, group string
		want        []string
	}{
		{name: "UDP-LISTEN", group: GroupUDP, want: []string{OptCapListen, OptCapIPFilter, OptCapPort, OptCapLowport}},
		{name: "UDP-RECVFROM", group: GroupUDP, want: []string{OptCapIPFilter, OptCapPort, OptCapLowport}},
		{name: "UNIX-RECVFROM", group: GroupUnix, want: nil},
		{name: "UNIX-LISTEN", group: GroupUnix, want: []string{OptCapListen}},
		{name: "TCP-LISTEN", group: GroupTCP, want: []string{OptCapListen, OptCapIPFilter, OptCapPort, OptCapLowport}},
		{name: "SOCKET-LISTEN", group: GroupSocket, want: []string{OptCapListen}},
		{name: "OPEN", group: GroupFiles, want: []string{OptCapOpen}},
		{name: "CREATE", group: GroupFiles, want: nil},
		{name: "POSIXMQ-RECV", group: GroupPOSIXMQ, want: []string{OptCapOpen}},
		{name: "UDP", group: GroupUDP, want: []string{OptCapPort, OptCapLowport}},
		{name: "QUIC", group: GroupQUIC, want: []string{OptCapPort}},
	}
	for _, tc := range cases {
		got := DerivedOptionCaps(tc.name, tc.group)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s/%s = %v want %v", tc.name, tc.group, got, tc.want)
		}
	}
}

func TestOptionCapsAllowed(t *testing.T) {
	if !OptionCapsAllowed([]string{OptCapListen}, []string{OptCapListen}) {
		t.Fatal("listen address should allow listen option")
	}
	if OptionCapsAllowed(nil, []string{OptCapListen}) {
		t.Fatal("address without listen cap must reject listen options")
	}
	if !OptionCapsAllowed([]string{OptCapListen}, nil) {
		t.Fatal("unrestricted option must be allowed")
	}
}
