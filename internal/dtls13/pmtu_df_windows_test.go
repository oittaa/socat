//go:build windows

package dtls13

import (
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func TestUnfragmentedProbesRequiresPMTUDISCProbe(t *testing.T) {
	for _, network := range []string{"udp4", "udp6", "udp"} {
		t.Run(network, func(t *testing.T) {
			conn, err := net.ListenUDP(network, &net.UDPAddr{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			ok, err := enableUnfragmentedSends(conn)
			if err != nil || !ok {
				t.Fatalf("enable: ok=%v err=%v", ok, err)
			}
			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			if err := raw.Control(func(fd uintptr) {
				h := windows.Handle(fd)
				assertProbe := func(level, opt int) {
					mode, err := windows.GetsockoptInt(h, level, opt)
					if err != nil || mode != windows.IP_PMTUDISC_PROBE {
						t.Errorf("level %d option %d = %d, %v; want PROBE", level, opt, mode, err)
					}
				}
				if network != "udp4" {
					assertProbe(windows.IPPROTO_IPV6, windows.IPV6_MTU_DISCOVER)
				}
				if network != "udp6" {
					assertProbe(windows.IPPROTO_IP, windows.IP_MTU_DISCOVER)
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
