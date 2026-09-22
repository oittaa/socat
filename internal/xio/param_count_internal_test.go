package xio

import "testing"

func TestBoundsFromSyntax(t *testing.T) {
	cases := []struct {
		syntax   string
		min, max int
	}{
		{syntax: "STDIO", min: 0, max: 0},
		{syntax: "STDIN", min: 0, max: 0},
		{syntax: "PTY", min: 0, max: 0},
		{syntax: "STALL", min: 0, max: 0},
		{syntax: "SOCKETPAIR", min: 0, max: 0},
		{syntax: "PIPE[:<filename>]", min: 0, max: 1},
		{syntax: "FIFO[:<filename>]", min: 0, max: 1},
		{syntax: "SHELL[:<shell-command>]", min: 0, max: 1},
		{syntax: "TUN[:<if-addr>/<bits>]", min: 0, max: 1},
		{syntax: "FD:<fdnum>", min: 1, max: 1},
		{syntax: "ACCEPT-FD:<fdnum>", min: 1, max: 1},
		{syntax: "OPEN:<filename>", min: 1, max: 1},
		{syntax: "CREATE:<filename>", min: 1, max: 1},
		{syntax: "GOPEN:<filename>", min: 1, max: 1},
		{syntax: "TEXT:<string>", min: 1, max: 1},
		{syntax: "EXEC:<command-line>", min: 1, max: 1},
		{syntax: "SYSTEM:<shell-command>", min: 1, max: 1},
		{syntax: "INTERFACE:<interface>", min: 1, max: 1},
		{syntax: "TCP-LISTEN:<port>", min: 1, max: 1},
		{syntax: "UDP-RECV:<port>", min: 1, max: 1},
		{syntax: "IP-RECV:<protocol>", min: 1, max: 1},
		{syntax: "OPENSSL-LISTEN:<port>", min: 1, max: 1},
		{syntax: "OPENSSL-DTLS-SERVER:<port>", min: 1, max: 1},
		{syntax: "VSOCK-LISTEN:<port>", min: 1, max: 1},
		{syntax: "POSIXMQ-READ:/<mqueue>", min: 1, max: 1},
		{syntax: "UNIX-CONNECT:<filename>", min: 1, max: 1},
		{syntax: "ABSTRACT-CONNECT:<string>", min: 1, max: 1},
		{syntax: "TCP:<host>:<port>", min: 2, max: 2},
		{syntax: "UDP-DATAGRAM:<address>:<port>", min: 2, max: 2},
		{syntax: "IP-SENDTO:<host>:<protocol>", min: 2, max: 2},
		{syntax: "OPENSSL:<host>:<port>", min: 2, max: 2},
		{syntax: "OPENSSL-DTLS-CLIENT:<host>:<port>", min: 2, max: 2},
		{syntax: "SCTP-CONNECT:<host>:<port>", min: 2, max: 2},
		{syntax: "VSOCK-CONNECT:<cid>:<port>", min: 2, max: 2},
		{syntax: "ECHO[:<filename>]", min: 0, max: 1},
		{syntax: "PROXY:<proxy>:<hostname>:<port>", min: 3, max: 3},
		{syntax: "SOCKS4:<socks-server>:<host>:<port>", min: 3, max: 3},
		{syntax: "SOCKS5:<socks-server>[:<socks-port>]:<target-host>:<target-port>", min: 3, max: 4},
		{syntax: "SOCKS5-LISTEN:<socks-server>[:<socks-port>]:<listen-host>:<listen-port>", min: 3, max: 4},
		{syntax: "SOCKET-CONNECT:<domain>:<protocol>:<remote-address>", min: 3, max: 3},
		{syntax: "SOCKET-LISTEN:<domain>:<protocol>:<local-address>", min: 3, max: 3},
		{syntax: "SOCKET-SENDTO:<domain>:<type>:<protocol>:<remote-address>", min: 4, max: 4},
		{syntax: "SOCKET-DATAGRAM:<domain>:<type>:<protocol>:<remote-address>", min: 4, max: 4},
		{syntax: "SOCKET-RECV:<domain>:<type>:<protocol>:<local-address>", min: 4, max: 4},
		{syntax: "SOCKET-RECVFROM:<domain>:<type>:<protocol>:<local-address>", min: 4, max: 4},
	}
	for _, tc := range cases {
		min, max := boundsFromSyntax(tc.syntax)
		if min != tc.min || max != tc.max {
			t.Errorf("%s: got %d..%d want %d..%d", tc.syntax, min, max, tc.min, tc.max)
		}
	}
}

func TestParamCountOverrides(t *testing.T) {
	cases := []struct {
		name     string
		syntax   string
		min, max int
	}{
		{name: "WS", syntax: "WS:<host>:<port>", min: 2, max: -1},
		{name: "WSS-CONNECT", syntax: "WSS-CONNECT:<host>:<port>", min: 2, max: -1},
		{name: "WS-LISTEN", syntax: "WS-LISTEN:<port>", min: 1, max: -1},
		{name: "WSS-L", syntax: "WSS-L:<port>", min: 1, max: -1},
	}
	for _, tc := range cases {
		got := paramCountFor(tc.name, tc.syntax)
		if got.Min != tc.min || got.Max != tc.max {
			t.Errorf("%s: got %d..%d want %d..%d", tc.name, got.Min, got.Max, tc.min, tc.max)
		}
	}
}
