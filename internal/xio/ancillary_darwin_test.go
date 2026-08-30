//go:build darwin

package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
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
	g := &Global{Log: logx.New()}
	handleIPv4CmsgDarwin(unix.IP_RECVDSTADDR, []byte{127, 0, 0, 1}, g)
	if g.SessionVars["IP_DSTADDR"] != "127.0.0.1" {
		t.Fatalf("IP_DSTADDR=%q", g.SessionVars["IP_DSTADDR"])
	}

	var dl [20]byte
	dl[5] = 2
	dl[8] = 'e'
	dl[9] = 'n'
	g2 := &Global{Log: logx.New()}
	handleIPv4CmsgDarwin(unix.IP_RECVIF, dl[:], g2)
	if g2.SessionVars["IP_IF"] != "en" {
		t.Fatalf("IP_IF=%q", g2.SessionVars["IP_IF"])
	}
}

func TestApplyAncillaryRecvDstaddrDarwin(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recvdstaddr,ip-recvif")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyAncillaryRecvOpts(fd, spec); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVDSTADDR)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("IP_RECVDSTADDR=%d want 1", got)
	}
	got, err = unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVIF)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("IP_RECVIF=%d want 1", got)
	}
}

func TestUDPRecvDstaddrLiveDarwin(t *testing.T) {
	spec, err := parse.ParseSpec("UDP-RECV:0,ip-recvdstaddr,ip-recvif")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	recv := pc.(*net.UDPConn)
	t.Cleanup(func() { _ = recv.Close() })

	send, err := net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	if _, err := send.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	oobBuffer := make([]byte, AncillaryBufferSize)
	n, oob, _, err := ReadUDPMsgWithBuffer(recv, buf, true, oobBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("payload=%q", buf[:n])
	}
	if len(oob) > 0 && &oob[0] != &oobBuffer[0] {
		t.Fatal("ReadUDPMsgWithBuffer did not reuse the supplied buffer")
	}
	g := &Global{}
	ProcessAncillary(oob, g)
	if g.SessionVars["IP_DSTADDR"] == "" && g.SessionVars["IP_IF"] == "" {
		t.Fatalf("ip-recvdstaddr/ip-recvif were a no-op; session env=%v oob=%d", g.SessionVars, len(oob))
	}
}

func TestDarwinIPv6RecvExtSockoptProbe(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	opts := []struct {
		name   string
		option string
		opt    int
	}{
		{"IPV6_RECVDSTOPTS", "ipv6-recvdstopts", unix.IPV6_RECVDSTOPTS},
		{"IPV6_RECVHOPOPTS", "ipv6-recvhopopts", unix.IPV6_RECVHOPOPTS},
		{"IPV6_RECVRTHDR", "ipv6-recvrthdr", unix.IPV6_RECVRTHDR},
		{"IPV6_RECVPATHMTU", "ipv6-recvpathmtu", unix.IPV6_RECVPATHMTU},
	}
	for _, o := range opts {
		e, found := lookupIPAncillary(o.option)
		if !found {
			t.Fatalf("%s missing from the ancillary matrix", o.option)
		}
		setErr := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, o.opt, 1)
		got, getErr := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, o.opt)
		roundTrip := setErr == nil && getErr == nil && got != 0
		advertised := e.supportedOnThisPlatform()
		switch {
		case roundTrip && !advertised:
			t.Errorf("%s setsockopt/getsockopt round-trips; advertise %s on Darwin", o.name, o.option)
		case advertised && !roundTrip:
			t.Errorf("%s advertised on Darwin but set=%v get=%d geterr=%v", o.name, setErr, got, getErr)
		}
	}
}

func TestDarwinIPv6BlobIntSetsockoptProbe(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	opts := []struct {
		name string
		opt  int
	}{
		{"IPV6_DSTOPTS", unix.IPV6_DSTOPTS},
		{"IPV6_HOPOPTS", unix.IPV6_HOPOPTS},
		{"IPV6_RTHDR", unix.IPV6_RTHDR},
		{"IPV6_HOPLIMIT", unix.IPV6_HOPLIMIT},
		{"IPV6_PKTINFO", unix.IPV6_PKTINFO},
	}
	for _, o := range opts {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, o.opt, 1); err == nil {
			t.Errorf("%s int setsockopt succeeded on Darwin; do not classify the public TYPE_INT name as an unimplementable blob without implementing it", o.name)
		}
	}
}
