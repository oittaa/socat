//go:build linux || darwin

package xio

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func multicastCapableInterface(t *testing.T) net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var docker, fallback net.Interface
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			return ifi
		}
		if ifi.Name == "docker0" {
			docker = ifi
			continue
		}
		if fallback.Name == "" {
			fallback = ifi
		}
	}
	if docker.Name != "" {
		return docker
	}
	if fallback.Name == "" {
		t.Skip("no multicast interface")
	}
	return fallback
}

func TestDialControlAppliesMulticastTTLLoopAndIf(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-multicast-ttl=9,ip-multicast-loop=0,ip-multicast-if=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc := c.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL); got != 9 {
		t.Fatalf("IP_MULTICAST_TTL=%d want 9", got)
	}
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP); got != 0 {
		t.Fatalf("IP_MULTICAST_LOOP=%d want 0", got)
	}
	if got := udpInet4Sockopt(t, uc, unix.IPPROTO_IP, unix.IP_MULTICAST_IF); got != [4]byte{127, 0, 0, 1} {
		t.Fatalf("IP_MULTICAST_IF=%v want 127.0.0.1", got)
	}
}

func TestListenControlAppliesMulticastTTL(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-RECV:0,ip-multicast-ttl=4,mcloop")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL); got != 4 {
		t.Fatalf("ListenControl IP_MULTICAST_TTL=%d want 4", got)
	}
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP); got != 1 {
		t.Fatalf("ListenControl IP_MULTICAST_LOOP=%d want 1 (bare flag)", got)
	}
}

func TestDialControlAppliesIPv6MulticastLoop(t *testing.T) {
	skipWithoutIPv6Loopback(t)
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-multicast-loop=0")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp6", nil)}
	c, err := d.Dial("udp6", "[::1]:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc := c.(*net.UDPConn)
	if got := udpLevelSockoptInt(t, uc, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP); got != 0 {
		t.Fatalf("IPV6_MULTICAST_LOOP=%d want 0", got)
	}
}

func TestIPv4SocketRejectsIPv6MulticastLoop(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ipv6-multicast-loop=0")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not supported on IPv4") {
		t.Fatalf("error=%v want not supported on IPv4", err)
	}
}

func TestNonLinuxRejectsFreebindAndTransparent(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux implements ip-freebind and ip-transparent")
	}
	for _, raw := range []string{
		"UDP4:127.0.0.1:9,ip-freebind",
		"TCP4:127.0.0.1:9,ip-transparent",
	} {
		spec, err := parse.ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
		c, err := d.Dial("udp4", "127.0.0.1:9")
		if c != nil {
			_ = c.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%s: error=%v want not supported", raw, err)
		}
	}
}

func TestIPv6RecvErrRejectedAtOpenSpecAndDialControl(t *testing.T) {
	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-recverr")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedRecvErr(spec); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("RejectUnsupportedRecvErr=%v", err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp6", nil)}
	c, err := d.Dial("udp6", "[::1]:9")
	if c != nil {
		_ = c.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "MSG_ERRQUEUE") {
		t.Fatalf("DialControl ipv6-recverr=%v want MSG_ERRQUEUE rejection", err)
	}
}

func TestMulticastLoopPacketEffect(t *testing.T) {
	ifi := multicastCapableInterface(t)
	local := firstIPv4(t, ifi)
	group := net.IPv4(239, 255, 76, 10)
	recvSpec, err := parse.ParseSpec("UDP4-RECV:0,reuseaddr,ip-add-membership=239.255.76.10:" + ifi.Name)
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(recvSpec)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	port := pc.LocalAddr().(*net.UDPAddr).Port
	dst := &net.UDPAddr{IP: group, Port: port}

	send := func(loop string) net.Conn {
		t.Helper()
		spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-multicast-ttl=1,ip-multicast-loop=" + loop + ",ip-multicast-if=" + local)
		if err != nil {
			t.Fatal(err)
		}
		d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
		c, err := d.Dial("udp4", dst.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	off := send("0")
	_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := off.Write([]byte("noloop")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("multicast-loop=0 delivered a locally sent packet")
	}

	on := send("1")
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := on.Write([]byte("loop")); err != nil {
		t.Fatal(err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("multicast-loop=1: %v", err)
	}
	if string(buf[:n]) != "loop" {
		t.Fatalf("payload=%q", buf[:n])
	}
}

func TestMulticastTTLAncillaryPacket(t *testing.T) {
	ifi := multicastCapableInterface(t)
	local := firstIPv4(t, ifi)
	group := net.IPv4(239, 255, 76, 11)
	recvSpec, err := parse.ParseSpec("UDP4-RECV:0,reuseaddr,ip-recvttl,ip-add-membership=239.255.76.11:" + ifi.Name)
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(recvSpec)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)
	port := uc.LocalAddr().(*net.UDPAddr).Port

	sendSpec, err := parse.ParseSpec("UDP4:127.0.0.1:9,ip-multicast-ttl=9,ip-multicast-loop=1,ip-multicast-if=" + local)
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(sendSpec, "udp4", nil)}
	c, err := d.Dial("udp4", (&net.UDPAddr{IP: group, Port: port}).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte("ttl")); err != nil {
		t.Fatal(err)
	}

	oob := make([]byte, unix.CmsgSpace(4))
	buf := make([]byte, 16)
	_ = uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, oobn, _, _, err := uc.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ttl" {
		t.Fatalf("payload=%q", buf[:n])
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	var ttl int
	found := false
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && (m.Header.Type == unix.IP_TTL || m.Header.Type == unix.IP_RECVTTL) {
			found = true
			switch {
			case len(m.Data) >= 4:
				ttl = int(binary.LittleEndian.Uint32(m.Data[:4]))
			case len(m.Data) >= 1:
				ttl = int(m.Data[0])
			}
		}
	}
	if !found {
		t.Fatalf("no IP_TTL/IP_RECVTTL cmsg (oobn=%d msgs=%d)", oobn, len(msgs))
	}
	if ttl != 9 {
		t.Fatalf("ancillary multicast TTL=%d want 9 (oobn=%d msgs=%d)", ttl, oobn, len(msgs))
	}
}

func udpLevelSockoptInt(t *testing.T, uc *net.UDPConn, level, opt int) int {
	t.Helper()
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), level, opt)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func udpInet4Sockopt(t *testing.T, uc *net.UDPConn, level, opt int) [4]byte {
	t.Helper()
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v [4]byte
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInet4Addr(int(fd), level, opt)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}
