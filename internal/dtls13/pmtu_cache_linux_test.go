//go:build linux

package dtls13

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var vethSeq atomic.Uint32

func TestUnfragmentedProbeBypassesCachedIPv4RouteMTU(t *testing.T) {
	a, b := routedVeth(t, false)
	payload := 700
	locked := 512
	installLockedHostRoute(t, a.name, b.ip4, locked, unix.RT_SCOPE_LINK)
	assertCachedMTUHonored(t, a.ip4, b.ip4, payload, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	assertProbeIgnoresCachedMTU(t, a.ip4, b.ip4, payload)
}

func TestUnfragmentedProbeBypassesCachedIPv6RouteMTU(t *testing.T) {
	a, b := routedVeth(t, true)
	payload := 1400
	locked := 1280
	installLockedHostRoute(t, a.name, b.ip6, locked, unix.RT_SCOPE_UNIVERSE)
	assertCachedMTUHonored(t, a.ip6, b.ip6, payload, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	assertProbeIgnoresCachedMTU(t, a.ip6, b.ip6, payload)
}

type vethEnd struct {
	name     string
	ip4, ip6 net.IP
}

func routedVeth(t *testing.T, ipv6 bool) (vethEnd, vethEnd) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	id := fmt.Sprintf("%d%02d", os.Getpid()%1000, vethSeq.Add(1))
	a := vethEnd{name: "pma" + id, ip4: net.ParseIP("192.0.2.1").To4(), ip6: net.ParseIP("2001:db8::1")}
	b := vethEnd{name: "pmb" + id, ip4: net.ParseIP("192.0.2.2").To4(), ip6: net.ParseIP("2001:db8::2")}
	createVeth(t, a.name, b.name)
	t.Cleanup(func() { _ = deleteLink(a.name) })
	linkUpMTU(t, a.name, 1500)
	linkUpMTU(t, b.name, 1500)
	if ipv6 {
		writeSysctl(t, "/proc/sys/net/ipv6/conf/"+a.name+"/accept_dad", "0")
		writeSysctl(t, "/proc/sys/net/ipv6/conf/"+b.name+"/accept_dad", "0")
		addAddr(t, a.name, a.ip6, 64, unix.IFA_F_NODAD)
		addAddr(t, b.name, b.ip6, 64, unix.IFA_F_NODAD)
	} else {
		addAddr(t, a.name, a.ip4, 24, 0)
		addAddr(t, b.name, b.ip4, 24, 0)
		writeSysctl(t, "/proc/sys/net/ipv4/conf/"+a.name+"/rp_filter", "0")
		writeSysctl(t, "/proc/sys/net/ipv4/conf/"+b.name+"/rp_filter", "0")
	}
	return a, b
}

func installLockedHostRoute(t *testing.T, dev string, dst net.IP, mtu int, scope uint8) {
	t.Helper()
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		t.Fatal(err)
	}
	family, dstLen := uint8(unix.AF_INET), uint8(32)
	raw := dst.To4()
	if raw == nil {
		family, dstLen, raw = unix.AF_INET6, 128, dst.To16()
	}
	body := rtmsg(family, dstLen, scope)
	body = append(body, nla(unix.RTA_DST, raw)...)
	body = append(body, nlaU32(unix.RTA_OIF, uint32(ifi.Index))...)
	metrics := append(nlaU32(unix.RTAX_LOCK, 1<<unix.RTAX_MTU), nlaU32(unix.RTAX_MTU, uint32(mtu))...)
	body = append(body, nla(unix.RTA_METRICS, metrics)...)
	nlDo(t, unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
}

func assertCachedMTUHonored(t *testing.T, src, dst net.IP, payload, proto, opt, mode int) {
	t.Helper()
	send, recv := udpPair(t, src, dst)
	setSockoptInt(t, send, proto, opt, mode)
	if err := writeUDP(send, recv.LocalAddr(), payload); !isMessageTooLong(err) {
		t.Fatalf("PMTUDISC_DO send of %d: %v (route lock should reject)", payload, err)
	}
}

func assertProbeIgnoresCachedMTU(t *testing.T, src, dst net.IP, payload int) {
	t.Helper()
	send, recv := udpPair(t, src, dst)
	ok, err := enableUnfragmentedSends(send)
	if err != nil || !ok {
		t.Fatalf("enableUnfragmentedSends: ok=%v err=%v", ok, err)
	}
	if src.To4() == nil {
		if mode := mtuDiscoverMode(t, send, true); mode != unix.IPV6_PMTUDISC_PROBE {
			t.Fatalf("probe socket IPV6_MTU_DISCOVER=%d want PROBE (not DO)", mode)
		}
	} else if mode := ipv4MTUDiscoverMode(t, send); mode != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("probe socket IP_MTU_DISCOVER=%d want PROBE (not DO)", mode)
	}
	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = recv.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := recv.ReadFrom(buf)
		if err != nil {
			got <- -1
			return
		}
		got <- n
	}()
	if err := writeUDP(send, recv.LocalAddr(), payload); err != nil {
		t.Fatalf("PMTUDISC_PROBE send of %d: %v", payload, err)
	}
	n := <-got
	if n != payload {
		t.Fatalf("probe datagram length %d want %d", n, payload)
	}
}

func udpPair(t *testing.T, src, dst net.IP) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	network := "udp4"
	if src.To4() == nil {
		network = "udp6"
	}
	recv, err := net.ListenUDP(network, &net.UDPAddr{IP: dst})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	send, err := net.ListenUDP(network, &net.UDPAddr{IP: src})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	return send, recv
}

func writeUDP(conn *net.UDPConn, addr net.Addr, n int) error {
	_, err := conn.WriteTo(make([]byte, n), addr)
	return err
}

func setSockoptInt(t *testing.T, conn *net.UDPConn, proto, opt, value int) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ctrlErr error
	if err := raw.Control(func(fd uintptr) {
		ctrlErr = unix.SetsockoptInt(int(fd), proto, opt, value)
	}); err != nil {
		t.Fatal(err)
	}
	if ctrlErr != nil {
		t.Fatal(ctrlErr)
	}
}

func writeSysctl(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil && !errors.Is(err, unix.ENOENT) {
		t.Fatal(err)
	}
}

const vethInfoPeer = 1

func createVeth(t *testing.T, a, b string) {
	t.Helper()
	peer := append(ifinfomsg(), nlaString(unix.IFLA_IFNAME, b)...)
	info := append(nlaString(unix.IFLA_INFO_KIND, "veth"), nla(unix.IFLA_INFO_DATA, nla(vethInfoPeer, peer))...)
	body := append(ifinfomsg(), nlaString(unix.IFLA_IFNAME, a)...)
	body = append(body, nla(unix.IFLA_LINKINFO, info)...)
	nlDo(t, unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

func deleteLink(name string) error {
	body := append(ifinfomsg(), nlaString(unix.IFLA_IFNAME, name)...)
	return nlRequest(unix.RTM_DELLINK, 0, body)
}

func linkUpMTU(t *testing.T, name string, mtu int) {
	t.Helper()
	msg := ifinfomsg()
	binary.NativeEndian.PutUint32(msg[8:12], unix.IFF_UP)
	binary.NativeEndian.PutUint32(msg[12:16], unix.IFF_UP)
	body := append(msg, nlaString(unix.IFLA_IFNAME, name)...)
	body = append(body, nlaU32(unix.IFLA_MTU, uint32(mtu))...)
	nlDo(t, unix.RTM_NEWLINK, 0, body)
}

func addAddr(t *testing.T, name string, ip net.IP, bits int, flags uint8) {
	t.Helper()
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	family := uint8(unix.AF_INET)
	raw := ip.To4()
	if raw == nil {
		family, raw = unix.AF_INET6, ip.To16()
	}
	msg := make([]byte, unix.SizeofIfAddrmsg)
	msg[0] = family
	msg[1] = uint8(bits)
	msg[2] = flags
	binary.NativeEndian.PutUint32(msg[4:8], uint32(ifi.Index))
	body := append(msg, nla(unix.IFA_LOCAL, raw)...)
	body = append(body, nla(unix.IFA_ADDRESS, raw)...)
	nlDo(t, unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

func ifinfomsg() []byte {
	return make([]byte, unix.SizeofIfInfomsg)
}

func rtmsg(family, dstLen, scope uint8) []byte {
	b := make([]byte, unix.SizeofRtMsg)
	b[0] = family
	b[1] = dstLen
	b[4] = unix.RT_TABLE_MAIN
	b[5] = unix.RTPROT_BOOT
	b[6] = scope
	b[7] = unix.RTN_UNICAST
	return b
}

func nlaString(typ uint16, s string) []byte {
	return nla(typ, append([]byte(s), 0))
}

func nlaU32(typ uint16, v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return nla(typ, b)
}

func nla(typ uint16, data []byte) []byte {
	nlaLen := 4 + len(data)
	b := make([]byte, (nlaLen+3)&^3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(nlaLen))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	return b
}

func nlDo(t *testing.T, typ, flags uint16, body []byte) {
	t.Helper()
	if err := nlRequest(typ, flags, body); err != nil {
		t.Fatal(err)
	}
}

func nlRequest(typ, flags uint16, body []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	local, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return errors.New("netlink getsockname")
	}
	tv := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	h := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRLEN + len(body)),
		Type:  typ,
		Flags: flags | unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   1,
		Pid:   local.Pid,
	}
	msg := make([]byte, h.Len)
	binary.NativeEndian.PutUint32(msg[0:4], h.Len)
	binary.NativeEndian.PutUint16(msg[4:6], h.Type)
	binary.NativeEndian.PutUint16(msg[6:8], h.Flags)
	binary.NativeEndian.PutUint32(msg[8:12], h.Seq)
	binary.NativeEndian.PutUint32(msg[12:16], h.Pid)
	copy(msg[unix.NLMSG_HDRLEN:], body)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	return parseNetlinkAck(buf[:n])
}

func parseNetlinkAck(b []byte) error {
	for len(b) >= unix.NLMSG_HDRLEN {
		mlen := int(binary.NativeEndian.Uint32(b[:4]))
		if mlen < unix.NLMSG_HDRLEN || mlen > len(b) {
			return errors.New("netlink message truncated")
		}
		typ := binary.NativeEndian.Uint16(b[4:6])
		if typ == unix.NLMSG_ERROR {
			if mlen < unix.NLMSG_HDRLEN+4 {
				return errors.New("netlink ack truncated")
			}
			code := int32(binary.NativeEndian.Uint32(b[unix.NLMSG_HDRLEN : unix.NLMSG_HDRLEN+4]))
			if code == 0 {
				return nil
			}
			return unix.Errno(-code)
		}
		aligned := (mlen + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if aligned <= 0 || aligned > len(b) {
			break
		}
		b = b[aligned:]
	}
	return errors.New("netlink ack missing")
}
