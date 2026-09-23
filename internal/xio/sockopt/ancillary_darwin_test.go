//go:build darwin

package sockopt

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSockaddrDLName(t *testing.T) {
	var buf [20]byte
	buf[5] = 2
	buf[8] = 'l'
	buf[9] = 'o'
	name, ok := sockaddrDLName(buf[:])
	if !ok || name != "lo" {
		t.Fatalf("name=%q ok=%v", name, ok)
	}
}

func TestProcessAncillaryRecvdstaddrRecvifDarwin(t *testing.T) {
	g := sessionVars{}
	handleIPv4CmsgDarwin(unix.IP_RECVDSTADDR, []byte{127, 0, 0, 1}, g)
	if g["IP_DSTADDR"] != "127.0.0.1" {
		t.Fatalf("IP_DSTADDR=%q", g["IP_DSTADDR"])
	}

	var dl [20]byte
	dl[5] = 2
	dl[8] = 'e'
	dl[9] = 'n'
	g2 := sessionVars{}
	handleIPv4CmsgDarwin(unix.IP_RECVIF, dl[:], g2)
	if g2["IP_IF"] != "en" {
		t.Fatalf("IP_IF=%q", g2["IP_IF"])
	}
}
