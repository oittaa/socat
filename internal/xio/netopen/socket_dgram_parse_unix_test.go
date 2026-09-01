//go:build linux || darwin

package netopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestParseSocketDgramParams(t *testing.T) {
	ipv4 := "x00007f000001"
	tests := []struct {
		name    string
		raw     string
		domain  int
		typ     int
		proto   int
		addr    []byte
		errPart string
	}{
		{
			name:    "malformed-domain",
			raw:     "SOCKET-SENDTO:abc:2:17:" + ipv4,
			errPart: "domain:",
		},
		{
			name:    "malformed-type",
			raw:     "SOCKET-SENDTO:2:abc:17:" + ipv4,
			errPart: "type:",
		},
		{
			name:    "malformed-protocol",
			raw:     "SOCKET-SENDTO:2:2:abc:" + ipv4,
			errPart: "protocol:",
		},
		{
			name:   "empty-type-defaults-dgram",
			raw:    "SOCKET-SENDTO:2::17:" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  17,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "empty-protocol-defaults-zero",
			raw:    "SOCKET-SENDTO:2:2::" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  0,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "empty-domain-is-unspec",
			raw:    "SOCKET-RECV::2:0:" + ipv4,
			domain: 0,
			typ:    unix.SOCK_DGRAM,
			proto:  0,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "sendto-explicit",
			raw:    "SOCKET-SENDTO:2:2:17:" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  17,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "datagram-explicit",
			raw:    "SOCKET-DATAGRAM:2:2:17:" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  17,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "recv-explicit",
			raw:    "SOCKET-RECV:2:2:0:" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  0,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "recvfrom-explicit",
			raw:    "SOCKET-RECVFROM:2:2:0:" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  0,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "hex-positionals",
			raw:    "SOCKET-SENDTO:0x2:0x2:0x11:" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  17,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
		{
			name:   "octal-protocol",
			raw:    "SOCKET-SENDTO:02:02:021:" + ipv4,
			domain: unix.AF_INET,
			typ:    unix.SOCK_DGRAM,
			proto:  17,
			addr:   []byte{0, 0, 127, 0, 0, 1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseSocketDgramParams(s)
			if tc.errPart != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("error=%v want %q", err, tc.errPart)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.domain != tc.domain || got.typ != tc.typ || got.proto != tc.proto {
				t.Fatalf("domain/type/proto=%d/%d/%d want %d/%d/%d",
					got.domain, got.typ, got.proto, tc.domain, tc.typ, tc.proto)
			}
			if string(got.addr) != string(tc.addr) {
				t.Fatalf("addr=%x want %x", got.addr, tc.addr)
			}
		})
	}
}
