//go:build linux

package dtls13

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var vethSeq atomic.Uint32

func TestUnfragmentedProbeBypassesCachedIPv4RouteMTU(t *testing.T) {
	p := routedVeth(t, false)
	payload := 700
	locked := 512
	installLockedHostRoute(t, p.a.name, p.b.ip4, locked, unix.RT_SCOPE_UNIVERSE)
	mustRouteMTU(t, p.b.ip4, locked)
	assertCachedMTUHonored(t, p, p.a.ip4, p.b.ip4, payload, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	assertProbeIgnoresCachedMTU(t, p, p.a.ip4, p.b.ip4, payload)
}

func TestUnfragmentedProbeBypassesCachedIPv6RouteMTU(t *testing.T) {
	p := routedVeth(t, true)
	payload := 1400
	locked := 1280
	installLockedHostRoute(t, p.a.name, p.b.ip6, locked, unix.RT_SCOPE_UNIVERSE)
	mustRouteMTU(t, p.b.ip6, locked)
	assertCachedMTUHonored(t, p, p.a.ip6, p.b.ip6, payload, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	assertProbeIgnoresCachedMTU(t, p, p.a.ip6, p.b.ip6, payload)
}

type vethEnd struct {
	name     string
	ip4, ip6 net.IP
	mac      net.HardwareAddr
}

type routedPath struct {
	a, b vethEnd
	ns   int
}

func routedVeth(t *testing.T, ipv6 bool) routedPath {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	id := fmt.Sprintf("%d%02d", os.Getpid()%1000, vethSeq.Add(1))
	p := routedPath{
		a:  vethEnd{name: "pma" + id, ip4: net.ParseIP("192.0.2.1").To4(), ip6: net.ParseIP("2001:db8::1")},
		b:  vethEnd{name: "pmb" + id, ip4: net.ParseIP("192.0.2.2").To4(), ip6: net.ParseIP("2001:db8::2")},
		ns: openNewNetNS(t),
	}
	createVeth(t, p.a.name, p.b.name)
	t.Cleanup(func() { _ = deleteLink(p.a.name) })
	linkUpMTU(t, p.a.name, 1500)
	p.a.mac = ifaceMAC(t, p.a.name)
	p.b.mac = ifaceMAC(t, p.b.name)
	moveLinkToNS(t, p.b.name, p.ns)
	if _, err := net.InterfaceByName(p.b.name); err == nil {
		t.Fatalf("%s still in the host namespace", p.b.name)
	}
	if ipv6 {
		writeSysctl(t, "/proc/sys/net/ipv6/conf/"+p.a.name+"/accept_dad", "0")
		addAddr(t, p.a.name, p.a.ip6, 64, unix.IFA_F_NODAD)
		addNeigh(t, p.a.name, p.b.ip6, p.b.mac)
		withNetNS(t, p.ns, func() {
			linkUpMTU(t, "lo", 65536)
			linkUpMTU(t, p.b.name, 1500)
			writeSysctl(t, "/proc/sys/net/ipv6/conf/"+p.b.name+"/accept_dad", "0")
			addAddr(t, p.b.name, p.b.ip6, 64, unix.IFA_F_NODAD)
			addNeigh(t, p.b.name, p.a.ip6, p.a.mac)
		})
	} else {
		addAddr(t, p.a.name, p.a.ip4, 24, 0)
		writeSysctl(t, "/proc/sys/net/ipv4/conf/"+p.a.name+"/rp_filter", "0")
		addNeigh(t, p.a.name, p.b.ip4, p.b.mac)
		withNetNS(t, p.ns, func() {
			linkUpMTU(t, "lo", 65536)
			linkUpMTU(t, p.b.name, 1500)
			addAddr(t, p.b.name, p.b.ip4, 24, 0)
			writeSysctl(t, "/proc/sys/net/ipv4/conf/all/rp_filter", "0")
			writeSysctl(t, "/proc/sys/net/ipv4/conf/default/rp_filter", "0")
			writeSysctl(t, "/proc/sys/net/ipv4/conf/"+p.b.name+"/rp_filter", "0")
			addNeigh(t, p.b.name, p.a.ip4, p.a.mac)
		})
	}
	return p
}

func assertCachedMTUHonored(t *testing.T, p routedPath, src, dst net.IP, payload, proto, opt, mode int) {
	t.Helper()
	send := listenUDP(t, src)
	setSockoptInt(t, send, proto, opt, mode)
	if err := writeUDP(send, &net.UDPAddr{IP: dst, Port: 9}, payload); !isMessageTooLong(err) {
		t.Fatalf("PMTUDISC_DO send of %d: %v (route lock should reject)", payload, err)
	}
}

func assertProbeIgnoresCachedMTU(t *testing.T, p routedPath, src, dst net.IP, payload int) {
	t.Helper()
	send := listenUDP(t, src)
	ok, err := enableUnfragmentedSends(send)
	if err != nil || !ok {
		t.Fatalf("enableUnfragmentedSends: ok=%v err=%v", ok, err)
	}
	ipv6 := src.To4() == nil
	if ipv6 {
		if mode := mtuDiscoverMode(t, send, true); mode != unix.IPV6_PMTUDISC_PROBE {
			t.Fatalf("probe socket IPV6_MTU_DISCOVER=%d want PROBE (not DO)", mode)
		}
	} else if mode := ipv4MTUDiscoverMode(t, send); mode != unix.IP_PMTUDISC_PROBE {
		t.Fatalf("probe socket IP_MTU_DISCOVER=%d want PROBE (not DO)", mode)
	}
	fd := openVethCapture(t, p.a.name, ipv6)
	defer func() { _ = unix.Close(fd) }()
	if err := writeUDP(send, &net.UDPAddr{IP: dst, Port: 9}, payload); err != nil {
		t.Fatalf("PMTUDISC_PROBE send of %d: %v", payload, err)
	}
	if got := readVethUDPPayload(t, fd, ipv6, payload); got != payload {
		t.Fatalf("veth TX UDP payload %d want %d", got, payload)
	}
}

func openVethCapture(t *testing.T, ifname string, ipv6 bool) int {
	t.Helper()
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatal(err)
	}
	eth := uint16(unix.ETH_P_ALL)
	proto := int(htons(eth))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: ifi.Index}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	return fd
}

func readVethUDPPayload(t *testing.T, fd int, ipv6 bool, want int) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 2048)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			t.Fatalf("veth TX missing UDP payload %d", want)
		}
		ms := int(remain / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, ms)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			continue
		}
		rn, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			t.Fatal(err)
		}
		ll, _ := from.(*unix.SockaddrLinklayer)
		if ll == nil || ll.Pkttype != unix.PACKET_OUTGOING || rn < 14 {
			continue
		}
		et := binary.BigEndian.Uint16(buf[12:14])
		if ipv6 && et != unix.ETH_P_IPV6 || !ipv6 && et != unix.ETH_P_IP {
			continue
		}
		if pl, ok := udpPayloadLen(buf[14:rn], ipv6); ok && pl == want {
			return pl
		}
	}
}

func udpPayloadLen(b []byte, ipv6 bool) (int, bool) {
	if ipv6 {
		if len(b) < 48 || b[0]>>4 != 6 || b[6] != unix.IPPROTO_UDP {
			return 0, false
		}
		plen := int(binary.BigEndian.Uint16(b[4:6]))
		if plen < 8 {
			return 0, false
		}
		return plen - 8, true
	}
	if len(b) < 28 || b[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(b[0]&0xf) * 4
	if ihl < 20 || len(b) < ihl+8 || b[9] != unix.IPPROTO_UDP {
		return 0, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl+8 {
		return 0, false
	}
	return total - ihl - 8, true
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
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

func mustRouteMTU(t *testing.T, dst net.IP, want int) {
	t.Helper()
	got, detail, err := lookupRouteMTU(dst)
	if err != nil {
		t.Fatalf("GETROUTE %s: %v (%s)", dst, err, detail)
	}
	if got != want {
		t.Fatalf("route MTU for %s = %d want %d (%s)", dst, got, want, detail)
	}
}

func lookupRouteMTU(dst net.IP) (int, string, error) {
	family, dstLen := uint8(unix.AF_INET), uint8(32)
	raw := dst.To4()
	if raw == nil {
		family, dstLen, raw = unix.AF_INET6, 128, dst.To16()
	}
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = family
	body[1] = dstLen
	body = append(body, nla(unix.RTA_DST, raw)...)
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, "", err
	}
	tv := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, "", err
	}
	h := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRLEN + len(body)),
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST,
		Seq:   1,
	}
	msg := make([]byte, h.Len)
	binary.NativeEndian.PutUint32(msg[0:4], h.Len)
	binary.NativeEndian.PutUint16(msg[4:6], h.Type)
	binary.NativeEndian.PutUint16(msg[6:8], h.Flags)
	binary.NativeEndian.PutUint32(msg[8:12], h.Seq)
	copy(msg[unix.NLMSG_HDRLEN:], body)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, "", err
	}
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, "", err
	}
	return parseRouteMTU(buf[:n])
}

func parseRouteMTU(b []byte) (int, string, error) {
	detail := fmt.Sprintf("raw=%x", b[:min(len(b), 256)])
	for len(b) >= unix.NLMSG_HDRLEN {
		mlen := int(binary.NativeEndian.Uint32(b[:4]))
		if mlen < unix.NLMSG_HDRLEN || mlen > len(b) {
			return 0, detail, errors.New("netlink message truncated")
		}
		typ := binary.NativeEndian.Uint16(b[4:6])
		if typ == unix.NLMSG_ERROR {
			code := int32(binary.NativeEndian.Uint32(b[unix.NLMSG_HDRLEN : unix.NLMSG_HDRLEN+4]))
			return 0, detail, unix.Errno(-code)
		}
		if typ == unix.RTM_NEWROUTE && mlen > unix.NLMSG_HDRLEN+unix.SizeofRtMsg {
			mtu := 0
			attrs := b[unix.NLMSG_HDRLEN+unix.SizeofRtMsg : mlen]
			rt := b[unix.NLMSG_HDRLEN : unix.NLMSG_HDRLEN+unix.SizeofRtMsg]
			detail = fmt.Sprintf("family=%d dst_len=%d table=%d proto=%d scope=%d type=%d", rt[0], rt[1], rt[4], rt[5], rt[6], rt[7])
			for len(attrs) >= 4 {
				al := int(binary.NativeEndian.Uint16(attrs[0:2]))
				at := binary.NativeEndian.Uint16(attrs[2:4])
				if al < 4 || al > len(attrs) {
					break
				}
				val := attrs[4:al]
				if at == unix.RTA_METRICS {
					m := val
					for len(m) >= 4 {
						ml := int(binary.NativeEndian.Uint16(m[0:2]))
						mt := binary.NativeEndian.Uint16(m[2:4])
						if ml < 4 || ml > len(m) {
							break
						}
						if mt == unix.RTAX_MTU && ml >= 8 {
							mtu = int(binary.NativeEndian.Uint32(m[4:8]))
						}
						detail += fmt.Sprintf(" metric[%d]=%d", mt, binary.NativeEndian.Uint32(m[4:min(ml, 8)]))
						m = m[(ml+3)&^3:]
					}
				}
				attrs = attrs[(al+3)&^3:]
			}
			return mtu, detail, nil
		}
		aligned := (mlen + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if aligned <= 0 || aligned > len(b) {
			break
		}
		b = b[aligned:]
	}
	return 0, detail, errors.New("GETROUTE missing")
}

func listenUDP(t *testing.T, ip net.IP) *net.UDPConn {
	t.Helper()
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
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
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ifaceMAC(t *testing.T, name string) net.HardwareAddr {
	t.Helper()
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(ifi.HardwareAddr) != 6 {
		t.Fatalf("%s MAC %v", name, ifi.HardwareAddr)
	}
	return append(net.HardwareAddr(nil), ifi.HardwareAddr...)
}

const threadNetNS = "/proc/thread-self/ns/net"

func openNewNetNS(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	safe := true
	defer func() {
		if safe {
			runtime.UnlockOSThread()
		}
	}()
	orig, err := unix.Open(threadNetNS, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(orig) }()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare CLONE_NEWNET: %v", err)
	}
	safe = false
	ns, err := unix.Open(threadNetNS, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var hostStat, nsStat unix.Stat_t
	if err := unix.Fstat(orig, &hostStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(ns, &nsStat); err != nil {
		t.Fatal(err)
	}
	if hostStat.Ino == nsStat.Ino {
		_ = unix.Close(ns)
		t.Fatal("unshare did not create a new network namespace")
	}
	if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(ns)
		t.Fatalf("restore netns: %v", err)
	}
	safe = true
	t.Cleanup(func() { _ = unix.Close(ns) })
	return ns
}

func withNetNS(t *testing.T, ns int, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	safe := true
	defer func() {
		if safe {
			runtime.UnlockOSThread()
		}
	}()
	orig, err := unix.Open(threadNetNS, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(orig) }()
	if err := unix.Setns(ns, unix.CLONE_NEWNET); err != nil {
		t.Fatalf("setns: %v", err)
	}
	safe = false
	defer func() {
		if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore netns: %v", err)
			return
		}
		safe = true
	}()
	fn()
}

func moveLinkToNS(t *testing.T, name string, nsfd int) {
	t.Helper()
	body := append(ifinfomsg(), nlaString(unix.IFLA_IFNAME, name)...)
	body = append(body, nlaU32(unix.IFLA_NET_NS_FD, uint32(nsfd))...)
	nlDo(t, unix.RTM_NEWLINK, 0, body)
}

func addNeigh(t *testing.T, dev string, dst net.IP, mac net.HardwareAddr) {
	t.Helper()
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		t.Fatal(err)
	}
	family := uint8(unix.AF_INET)
	raw := dst.To4()
	if raw == nil {
		family, raw = unix.AF_INET6, dst.To16()
	}
	msg := make([]byte, unix.SizeofNdMsg)
	msg[0] = family
	binary.NativeEndian.PutUint32(msg[4:8], uint32(ifi.Index))
	binary.NativeEndian.PutUint16(msg[8:10], unix.NUD_PERMANENT)
	body := append(msg, nla(unix.NDA_DST, raw)...)
	body = append(body, nla(unix.NDA_LLADDR, []byte(mac))...)
	nlDo(t, unix.RTM_NEWNEIGH, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
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
	if family == unix.AF_INET && bits == 24 && len(raw) == 4 {
		bcast := append(net.IP(nil), raw...)
		bcast[3] = 255
		body = append(body, nla(unix.IFA_BROADCAST, bcast)...)
	}
	if flags != 0 {
		body = append(body, nlaU32(unix.IFA_FLAGS, uint32(flags))...)
	}
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
	defer func() { _ = unix.Close(fd) }()
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
