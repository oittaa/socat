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
		{name: "UDP-LISTEN", group: GroupUDP, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-udp", "listen", "child", "range"})},
		{name: "UDP-RECVFROM", group: GroupUDP, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-udp", "child", "range"})},
		{name: "UNIX-RECVFROM", group: GroupUnix, want: uniqueCaps([]string{"fd", "named", "socket", "sock-unix", "retry", "child"})},
		{name: "UNIX-LISTEN", group: GroupUnix, want: uniqueCaps([]string{"fd", "named", "socket", "sock-unix", "listen", "child", "retry"})},
		{name: "TCP-LISTEN", group: GroupTCP, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-tcp", "listen", "child", "range", "retry"})},
		{name: "SOCKET-LISTEN", group: GroupSocket, want: uniqueCaps([]string{"fd", "socket", "listen", "range", "child", "retry"})},
		{name: "OPEN", group: GroupFiles, want: uniqueCaps([]string{"fd", "fifo", "chr", "blk", "reg", "named", "open", "termios"})},
		{name: "CREATE", group: GroupFiles, want: uniqueCaps([]string{"fd", "named", "reg"})},
		{name: "POSIXMQ-RECV", group: GroupPOSIXMQ, want: uniqueCaps([]string{"fd", "open", "named", "posixmq", "retry", "child"})},
		{name: "UDP", group: GroupUDP, want: uniqueCaps([]string{"fd", "socket", "sock-ip4", "sock-ip6", "ip-udp"})},
		{name: "QUIC", group: GroupQUIC, want: uniqueCaps(ClassicAddressCaps("QUIC"))},
		{name: "TLS-LISTEN", group: GroupTLS, want: uniqueCaps(ClassicAddressCaps("OPENSSL-LISTEN"))},
		{name: "WS", group: GroupWebSocket, want: uniqueCaps(ClassicAddressCaps("TCP-CONNECT"))},
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

func TestClassicAllowsOption(t *testing.T) {
	cases := []struct {
		addr, opt string
		want      bool
	}{
		{"TCP-CONNECT", "readbytes", true},
		{"TCP-CONNECT", "crnl", true},
		{"TCP-CONNECT", "cr", true},
		{"TCP-CONNECT", "shut-down", true},
		{"TCP-CONNECT", "setsid", true},
		{"TCP-CONNECT", "pty", false},
		{"TCP-CONNECT", "echo", false},
		{"TCP-CONNECT", "excl", false},
		{"TCP-CONNECT", "append", true},
		{"TCP-CONNECT", "ftruncate", false},
		{"FD", "ftruncate", true},
		{"FD", "append", true},
		{"EXEC", "append", true},
		{"STDIO", "append", true},
		{"TCP-CONNECT", "fork", true},
		{"UDP-CONNECT", "fork", false},
		{"UDP-CONNECT", "lowport", true},
		{"UDP-LISTEN", "accept-timeout", true},
		{"UDP-RECVFROM", "accept-timeout", false},
		{"UDP-RECVFROM", "range", true},
		{"UNIX-RECVFROM", "range", false},
		{"UNIX-RECVFROM", "accept-timeout", false},
		{"CREATE", "excl", false},
		{"OPEN", "excl", true},
		{"EXEC", "pty", true},
		{"EXEC", "fork", false},
		{"TCP-LISTEN", "sourceport", true},
		{"OPEN", "sourceport", false},
		{"TUN", "rcvtimeo", false},
		{"INTERFACE", "rcvtimeo", true},
		{"OPENSSL", "cert", true},
		{"TCP-CONNECT", "cert", false},
		{"QUIC", "lowport", true},
		{"WS", "nodelay", true},
		{"TCP", "noatime", true},
		{"UDP4", "pktinfo", true},
		{"OPEN", "noatime", true},
		{"CREATE", "pktinfo", false},
		{"OPEN", "o-direct", true},
		{"PIPE", "o-direct", true},
		{"CREATE", "o-direct", false},
		{"OPEN", "o-sync", true},
		{"PIPE", "o-sync", true},
		{"CREATE", "o-sync", false},
		{"FD", "o-sync", false},
		{"OPEN", "async", true},
		{"FD", "async", true},
		{"TCP-CONNECT", "async", true},
		{"CREATE", "async", true},
		{"OPEN", "lseek", true},
		{"FD", "lseek", true},
		{"TCP-CONNECT", "lseek", false},
		{"PIPE", "lseek", false},
		{"FD", "flock", true},
		{"TCP-CONNECT", "flock", true},
		{"OPEN", "flock", true},
		{"FD", "perm-late", true},
		{"OPEN", "perm-late", true},
		{"TCP-CONNECT", "perm-late", true},
		{"OPEN", "fs-noatime", true},
		{"CREATE", "fs-noatime", true},
		{"FD", "fs-noatime", true},
		{"PIPE", "fs-noatime", false},
		{"EXEC", "fs-noatime", false},
		{"OPEN", "fs-append", true},
		{"CREATE", "fs-append", true},
		{"FD", "fs-append", true},
		{"PIPE", "fs-append", false},
		{"EXEC", "fs-append", false},
		{"TCP", "fs-append", false},
		{"OPEN", "nodump", true},
		{"TCP", "nodump", false},
		{"PIPE", "ext2-nodump", false},
		{"OPEN", "notail", true},
		{"EXEC", "fs-immutable", false},
		{"UDP4", "ipv6-join-group", false},
		{"UDP4-RECV", "ipv6-join-group", false},
		{"TCP4", "ipv6-join-group", false},
		{"IP4", "ipv6-join-group", false},
		{"UDP6", "ipv6-join-group", true},
		{"UDP6-RECV", "ipv6-join-group", true},
		{"TCP6", "ipv6-join-group", true},
		{"UDP4", "ip-add-membership", true},
		{"UDP6", "ip-add-membership", true},
		{"UDP4", "join-group", false},
		{"UDP6", "join-group", true},
		{"UDP4", "add-membership", true},
		{"UDP4", "membership", true},
		{"UDP4", "ipv6-multicast-loop", false},
		{"UDP6", "ipv6-multicast-loop", true},
		{"TCP4", "mcloop6", false},
		{"TCP6", "mcloop6", true},
		{"UDP4", "ipv6-join-source-group", false},
		{"UDP6", "ipv6-join-source-group", true},
		{"UDP4", "join-source-group", false},
		{"UDP6", "join-source-group", true},
		{"UDP4", "ip-add-source-membership", true},
		{"UDP6", "ip-add-source-membership", true},
		{"UDP4", "ip-multicast-ttl", true},
		{"TCP", "ip-freebind", true},
		{"TCP", "ip-transparent", true},
		{"UDPLITE-CONNECT", "udplite-send-cscov", true},
		{"UDPLITE-CONNECT", "udplite-recv-cscov", true},
		{"UDPLITE-LISTEN", "udplite-send-cscov", true},
		{"UDPLITE4-RECVFROM", "udplite-recv-cscov", true},
		{"TCP-CONNECT", "udplite-send-cscov", false},
		{"UDP-CONNECT", "udplite-send-cscov", false},
	}
	for _, tc := range cases {
		got := ClassicAllowsOption(tc.addr, tc.opt)
		if got != tc.want {
			t.Errorf("ClassicAllowsOption(%s, %s)=%v want %v", tc.addr, tc.opt, got, tc.want)
		}
	}
}
