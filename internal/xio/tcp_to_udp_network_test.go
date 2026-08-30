package xio

import "testing"

func TestTCPToUDPNetwork(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{in: "tcp4", want: "udp4"},
		{in: "TCP4", want: "udp4"},
		{in: "tcp6", want: "udp6"},
		{in: "TCP6", want: "udp6"},
		{in: "tcp", want: "udp"},
		{in: "TCP", want: "udp"},
		{in: "", want: "udp"},
		{in: "unix", want: "udp"},
	}
	for _, tc := range tests {
		if got := TCPToUDPNetwork(tc.in); got != tc.want {
			t.Errorf("TCPToUDPNetwork(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}
