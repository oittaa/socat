package xio

import (
	"reflect"
	"testing"
)

func TestNamedOptionCaps(t *testing.T) {
	cases := []struct {
		name string
		got  []string
		want []string
	}{
		{name: "CapsUDPListen", got: CapsUDPListen, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-udp", "listen", "child", "range"})},
		{name: "CapsUDPRecvfrom", got: CapsUDPRecvfrom, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-udp", "child", "range"})},
		{name: "CapsUNIXRecvfrom", got: CapsUNIXRecvfrom, want: uniqueCaps([]string{"fd", "named", "socket", "sock-unix", "retry", "child"})},
		{name: "CapsUNIXListen", got: CapsUNIXListen, want: uniqueCaps([]string{"fd", "named", "socket", "sock-unix", "listen", "child", "retry"})},
		{name: "CapsTCPListen", got: CapsTCPListen, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-tcp", "listen", "child", "range", "retry"})},
		{name: "CapsSocketListen", got: CapsSocketListen, want: uniqueCaps([]string{"fd", "socket", "listen", "range", "child", "retry"})},
		{name: "CapsOpen", got: CapsOpen, want: uniqueCaps([]string{"fd", "fifo", "chr", "blk", "reg", "named", "open", "termios"})},
		{name: "CapsAcceptFD", got: CapsAcceptFD, want: uniqueCaps([]string{"fd", "socket", "sock-unix", "sock-ip4", "sock-ip6", "ip-udp", "ip-tcp", "ip-sctp", "ip-dccp", "ip-udplite", "child", "range", "retry"})},
		{name: "CapsCreate", got: CapsCreate, want: uniqueCaps([]string{"fd", "named", "reg"})},
		{name: "CapsPOSIXMQChild", got: CapsPOSIXMQChild, want: uniqueCaps([]string{"fd", "open", "named", "posixmq", "retry", "child"})},
		{name: "CapsUDPConnect", got: CapsUDPConnect, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-udp"})},
		{name: "CapsQUICConnect", got: CapsQUICConnect, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-udp", "child", "openssl", "retry"})},
		{name: "CapsTLSListen", got: CapsTLSListen, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-tcp", "listen", "child", "range", "openssl", "retry"})},
		{name: "CapsTCPConnect", got: CapsTCPConnect, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-tcp", "child", "retry"})},
		{name: "CapsAbstractListen", got: CapsAbstractListen, want: uniqueCaps([]string{"fd", "socket", "sock-unix", "listen", "child", "retry"})},
		{name: "CapsUNIXConnect", got: CapsUNIXConnect, want: uniqueCaps([]string{"fd", "named", "socket", "sock-unix", "retry"})},
	}
	for _, tc := range cases {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s = %v want %v", tc.name, tc.got, tc.want)
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
