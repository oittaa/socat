//go:build privileged && linux

package privileged_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/testcert"
	"golang.org/x/sys/unix"
)

const routedMTU = 1280

var pmtuNamespaceID atomic.Uint32

// All links and routes live in three disposable namespaces; the host network
// is unchanged. The router's egress, not the sender's interface, limits PMTU.
type dtlsRoute struct {
	t                             *testing.T
	client, router, server        string
	dst                           net.IP
	network, firewall             string
	level, discover, mtu, recverr int
	ceiling                       int
}

func newDTLSRoute(t *testing.T, ipv6 bool) *dtlsRoute {
	t.Helper()
	id := fmt.Sprintf("socat-pmtu-%d-%d", os.Getpid(), pmtuNamespaceID.Add(1))
	p := &dtlsRoute{t: t, client: id + "c", router: id + "r", server: id + "s",
		network: "udp4", firewall: "iptables", dst: net.ParseIP("198.51.100.2"),
		level: unix.IPPROTO_IP, discover: unix.IP_MTU_DISCOVER, mtu: unix.IP_MTU, recverr: unix.IP_RECVERR, ceiling: 1472}
	clientAddr, clientGW, serverAddr, serverGW := "192.0.2.2/24", "192.0.2.1", "198.51.100.2/24", "198.51.100.1"
	prefix, forward := "/24", "net.ipv4.ip_forward=1"
	if ipv6 {
		p.network, p.firewall = "udp6", "ip6tables"
		p.dst = net.ParseIP("2001:db8:2::2")
		p.level, p.discover, p.mtu, p.recverr, p.ceiling = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_MTU, unix.IPV6_RECVERR, 1452
		clientAddr, clientGW, serverAddr, serverGW = "2001:db8:1::2/64", "2001:db8:1::1", "2001:db8:2::2/64", "2001:db8:2::1"
		prefix, forward = "/64", "net.ipv6.conf.all.forwarding=1"
	}
	for _, ns := range []string{p.client, p.router, p.server} {
		p.command("ip", "netns", "add", ns)
		t.Cleanup(func() { p.command("ip", "netns", "del", ns) })
		if ipv6 {
			// These isolated addresses are unique; avoid startup DAD packet loss.
			p.run(ns, "sysctl", "-qw", "net.ipv6.conf.default.accept_dad=0")
		}
		p.run(ns, "ip", "link", "set", "lo", "up")
	}
	for _, link := range []struct{ ns, end, routerEnd string }{{p.client, "eth0", "left"}, {p.server, "eth0", "right"}} {
		p.run(p.router, "ip", "link", "add", link.routerEnd, "type", "veth", "peer", "name", "peer")
		p.run(p.router, "ip", "link", "set", "peer", "netns", link.ns)
		p.run(link.ns, "ip", "link", "set", "peer", "name", link.end)
		p.run(link.ns, "ip", "link", "set", link.end, "mtu", "1500", "up")
		p.run(p.router, "ip", "link", "set", link.routerEnd, "mtu", "1500", "up")
	}
	for _, addr := range []struct{ ns, dev, cidr string }{
		{p.client, "eth0", clientAddr}, {p.router, "left", clientGW + prefix},
		{p.server, "eth0", serverAddr}, {p.router, "right", serverGW + prefix},
	} {
		args := []string{"ip", "addr", "add", addr.cidr, "dev", addr.dev}
		if ipv6 {
			args = append(args, "nodad")
		}
		p.run(addr.ns, args...)
	}
	p.run(p.client, "ip", "route", "add", "default", "via", clientGW)
	p.run(p.server, "ip", "route", "add", "default", "via", serverGW)
	p.run(p.router, "sysctl", "-qw", forward)
	return p
}

func (p *dtlsRoute) command(program string, args ...string) string {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, program, args...).CombinedOutput()
	if err != nil {
		p.t.Fatalf("%s %v: %v\n%s", program, args, err, out)
	}
	return string(out)
}

func (p *dtlsRoute) run(ns string, args ...string) string {
	p.t.Helper()
	return p.command("ip", append([]string{"netns", "exec", ns}, args...)...)
}

func (p *dtlsRoute) pathMTU(n int) {
	p.t.Helper()
	p.run(p.router, "ip", "link", "set", "right", "mtu", strconv.Itoa(n))
}

func (p *dtlsRoute) blockPTB() {
	p.t.Helper()
	protocol, option, kind := "icmp", "--icmp-type", "fragmentation-needed"
	if p.network == "udp6" {
		protocol, option, kind = "ipv6-icmp", "--icmpv6-type", "packet-too-big"
	}
	p.run(p.router, p.firewall, "-A", "OUTPUT", "-p", protocol, option, kind, "-j", "DROP")
}

func (p *dtlsRoute) assertBlockedPTB() {
	p.t.Helper()
	out := p.run(p.router, p.firewall, "-nvx", "-L", "OUTPUT")
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[2] == "DROP" {
			if n, err := strconv.Atoi(fields[0]); err == nil && n > 0 {
				return
			}
		}
	}
	p.t.Fatalf("router did not drop a Packet Too Big message:\n%s", out)
}

func inPMTUNamespace(t *testing.T, name string, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	safe := true
	defer func() {
		if safe {
			runtime.UnlockOSThread()
		}
	}()
	saved, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(saved) }()
	ns, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(ns) }()
	if err := unix.Setns(ns, unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	safe = false
	defer func() {
		if err := unix.Setns(saved, unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore namespace: %v", err)
			return
		}
		safe = true
	}()
	fn()
}

func (p *dtlsRoute) socket(ns string, remote *net.UDPAddr) *net.UDPConn {
	p.t.Helper()
	var conn *net.UDPConn
	inPMTUNamespace(p.t, ns, func() {
		var err error
		if remote == nil {
			conn, err = net.ListenUDP(p.network, &net.UDPAddr{})
		} else {
			conn, err = net.DialUDP(p.network, nil, remote)
		}
		if err != nil {
			p.t.Fatal(err)
		}
	})
	p.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (p *dtlsRoute) sockopt(conn *net.UDPConn, opt int, value *int) int {
	p.t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		p.t.Fatal(err)
	}
	var result int
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		if value != nil {
			optErr = unix.SetsockoptInt(int(fd), p.level, opt, *value)
		} else {
			result, optErr = unix.GetsockoptInt(int(fd), p.level, opt)
		}
	}); err != nil {
		p.t.Fatal(err)
	}
	if optErr != nil {
		p.t.Fatal(optErr)
	}
	return result
}

func (p *dtlsRoute) pair(clientPC, serverPC *net.UDPConn) (*dtls13.Conn, net.Conn) {
	p.t.Helper()
	ca, err := testcert.NewAuthority("routed PMTU CA")
	if err != nil {
		p.t.Fatal(err)
	}
	cert, err := ca.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, []string{"localhost"})
	if err != nil {
		p.t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	listener, err := dtls13.Listen(serverPC, &dtls13.Config{Certificates: []tls.Certificate{cert.TLS()}})
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(p.t.Context(), 20*time.Second)
	defer cancel()
	remote := &net.UDPAddr{IP: p.dst, Port: serverPC.LocalAddr().(*net.UDPAddr).Port}
	client, err := dtls13.Client(ctx, clientPC, remote, &dtls13.Config{
		RootCAs: roots, ServerName: "localhost", MTU: p.ceiling, UnfragmentedProbes: true,
	})
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptContext(ctx)
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func pmtuExchange(t *testing.T, client, server net.Conn, size int) {
	t.Helper()
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	payload := bytes.Repeat([]byte{0xa5}, size)
	if n, err := client.Write(payload); err != nil || n != size {
		t.Fatalf("send %d: %d, %v", size, n, err)
	}
	buf := make([]byte, 2048)
	if n, err := server.Read(buf); err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("receive %d: %d, %v", size, n, err)
	}
	receipt := []byte("authenticated receipt")
	if _, err := server.Write(receipt); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(buf); err != nil || !bytes.Equal(buf[:n], receipt) {
		t.Fatalf("receipt: %d, %v", n, err)
	}
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
}

// Capture actual Ethernet output, including fragment flags and complete IP/UDP
// lengths. Packet receipt alone could otherwise succeed through fragmentation.
func (p *dtlsRoute) capture() int {
	p.t.Helper()
	fd := -1
	inPMTUNamespace(p.t, p.client, func() {
		iface, err := net.InterfaceByName("eth0")
		if err != nil {
			p.t.Fatal(err)
		}
		var proto [2]byte
		binary.BigEndian.PutUint16(proto[:], unix.ETH_P_ALL)
		protocol := binary.NativeEndian.Uint16(proto[:])
		fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(protocol))
		if err != nil {
			p.t.Fatal(err)
		}
		p.t.Cleanup(func() { _ = unix.Close(fd) })
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: iface.Index}); err != nil {
			p.t.Fatal(err)
		}
	})
	return fd
}

func (p *dtlsRoute) nextDatagram(fd, port int, deadline time.Time) int {
	p.t.Helper()
	buf := make([]byte, 65536)
	for {
		wait := time.Until(deadline)
		if wait <= 0 {
			p.t.Fatal("timed out waiting for routed DTLS output")
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, int(wait.Milliseconds())+1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			p.t.Fatal(err)
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			p.t.Fatal(err)
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || ll.Pkttype != unix.PACKET_OUTGOING || n < 14+20 {
			continue
		}
		ip := buf[14:n]
		var udp []byte
		if binary.BigEndian.Uint16(buf[12:14]) == unix.ETH_P_IP && p.network == "udp4" {
			if ip[9] != unix.IPPROTO_UDP {
				continue
			}
			if binary.BigEndian.Uint16(ip[6:8])&0x7fff != 0x4000 {
				p.t.Fatal("IPv4 DTLS output fragmented or missing DF")
			}
			if int(binary.BigEndian.Uint16(ip[2:4])) != len(ip) {
				p.t.Fatal("truncated IPv4 capture")
			}
			udp = ip[int(ip[0]&15)*4:]
		} else if binary.BigEndian.Uint16(buf[12:14]) == unix.ETH_P_IPV6 && p.network == "udp6" {
			if len(ip) < 40 {
				p.t.Fatal("short IPv6 capture")
			}
			if ip[6] == unix.IPPROTO_FRAGMENT {
				p.t.Fatal("IPv6 DTLS output fragmented")
			}
			if ip[6] != unix.IPPROTO_UDP {
				continue
			}
			if int(binary.BigEndian.Uint16(ip[4:6]))+40 != len(ip) {
				p.t.Fatal("truncated IPv6 capture")
			}
			udp = ip[40:]
		} else {
			continue
		}
		if len(udp) < 8 || int(binary.BigEndian.Uint16(udp[:2])) != port {
			continue
		}
		if int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) {
			p.t.Fatal("truncated UDP capture")
		}
		return len(udp) - 8
	}
}

func TestDTLSRoutedPMTU(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			t.Parallel()
			p := newDTLSRoute(t, ipv6)
			p.blockPTB()
			clientPC, serverPC := p.socket(p.client, nil), p.socket(p.server, nil)
			client, server := p.pair(clientPC, serverPC)
			capture := p.capture()
			initial := client.MaxDatagramSize()
			if initial <= routedMTU {
				t.Fatalf("initial application limit %d must exceed the later bottleneck %d", initial, routedMTU)
			}
			pmtuExchange(t, client, server, initial)
			p.pathMTU(routedMTU)
			// A smaller record keeps the association active; periodic confirmation
			// must detect the black hole without application ACKs or ICMP feedback.
			pmtuExchange(t, client, server, 64)
			port := clientPC.LocalAddr().(*net.UDPAddr).Port
			deadline := time.Now().Add(150 * time.Second)
			for client.MaxDatagramSize() >= initial {
				if p.nextDatagram(capture, port, deadline) > 200 {
					pmtuExchange(t, client, server, 64)
				}
			}
			shrunk := client.MaxDatagramSize()
			p.assertBlockedPTB()
			pmtuExchange(t, client, server, shrunk)
			p.pathMTU(1500)
			// Restore while recovery's confirm/search is active, without changing
			// production timers or waiting ten minutes for a new raise cycle.
			deadline = time.Now().Add(90 * time.Second)
			for client.MaxDatagramSize() < initial-20 {
				if p.nextDatagram(capture, port, deadline) > 200 {
					pmtuExchange(t, client, server, 64)
				}
			}
			grown := client.MaxDatagramSize()
			pmtuExchange(t, client, server, grown)
			for p.nextDatagram(capture, port, deadline) < grown {
			}
			t.Logf("application limit: %d -> %d -> %d; downstream IP MTU 1500 -> 1280 -> 1500, PTB blocked", initial, shrunk, grown)
		})
	}
}

func TestDTLSBypassesLearnedPMTUCache(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			t.Parallel()
			p := newDTLSRoute(t, ipv6)
			p.pathMTU(routedMTU)
			serverPC := p.socket(p.server, nil)
			remote := &net.UDPAddr{IP: p.dst, Port: serverPC.LocalAddr().(*net.UDPAddr).Port}
			control := p.socket(p.client, remote)
			do, one := unix.IP_PMTUDISC_DO, 1
			p.sockopt(control, p.discover, &do)
			p.sockopt(control, p.recverr, &one)
			if mtu := p.sockopt(control, p.mtu, nil); mtu != 1500 {
				t.Fatalf("initial route MTU = %d", mtu)
			}
			if n, err := control.Write(make([]byte, 1400)); n != 1400 || err != nil {
				t.Fatalf("initial DO send: %d, %v", n, err)
			}
			if err := control.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := control.Read(make([]byte, 2048)); !errors.Is(err, unix.EMSGSIZE) {
				t.Fatalf("router PTB: %v", err)
			}
			if mtu := p.sockopt(control, p.mtu, nil); mtu != routedMTU {
				t.Fatalf("ICMP-learned PMTU = %d, want %d", mtu, routedMTU)
			}
			p.pathMTU(1500)
			assertStale := func() {
				t.Helper()
				if n, err := control.Write(make([]byte, 1400)); n != 0 || !errors.Is(err, unix.EMSGSIZE) {
					t.Fatalf("DO must still honor stale cache: %d, %v", n, err)
				}
			}
			assertStale()
			clientPC := p.socket(p.client, nil)
			client, server := p.pair(clientPC, serverPC)
			capture := p.capture()
			size := client.MaxDatagramSize()
			if size <= routedMTU {
				t.Fatalf("test payload %d does not exceed stale IP PMTU", size)
			}
			pmtuExchange(t, client, server, size)
			deadline := time.Now().Add(5 * time.Second)
			for p.nextDatagram(capture, clientPC.LocalAddr().(*net.UDPAddr).Port, deadline) < size {
			}
			assertStale()
			t.Logf("authenticated %d-byte application datagram bypassed ICMP-learned PMTU %d; DO still rejected 1400 bytes", size, routedMTU)
		})
	}
}
