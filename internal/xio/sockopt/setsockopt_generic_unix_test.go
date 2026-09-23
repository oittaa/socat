//go:build linux || darwin

package sockopt

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplyTCPConnOptsSetsockoptIntKeepaliveUnix(t *testing.T) {
	cli, srv := tcpPair(t)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt-int=%d:%d:1", SOLSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGenericSetsockoptToNetConn(cli, mustDecodeAddress(t, spec), SockoptPhaseConnected); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("client SO_KEEPALIVE=%d want enabled", got)
	}
	if err := ApplyGenericSetsockoptToNetConn(srv, mustDecodeAddress(t, spec), SockoptPhaseConnected); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, srv, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("accepted SO_KEEPALIVE=%d want enabled", got)
	}
}

func TestApplyTCPConnOptsSetsockoptDalanHexUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, 1)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt=%d:%d:x%s", SOLSocket, soKeepalive, hex.EncodeToString(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGenericSetsockoptToNetConn(cli, mustDecodeAddress(t, spec), SockoptPhaseConnected); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled after dalan hex", got)
	}
}

func TestApplyTCPConnOptsSetsockoptConnectedAliasUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,sockopt-conn=%d:%d:1", SOLSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGenericSetsockoptToNetConn(cli, mustDecodeAddress(t, spec), SockoptPhaseConnected); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled", got)
	}
}

func TestApplyTCPConnOptsSetsockoptThroughNetConnUnwrapUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt-int=%d:%d:1", SOLSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGenericSetsockoptToNetConn(netConnUnwrapper{Conn: cli}, mustDecodeAddress(t, spec), SockoptPhaseConnected); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled through NetConn unwrap", got)
	}
}

func TestApplyUDPConnOptsAppliesSetsockoptUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UDP4:127.0.0.1:9,setsockopt=%d:%d:1", SOLSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(c, mustDecodeAddress(t, spec), "udp4"); err != nil {
		t.Fatalf("UDP setsockopt must apply, not no-op: %v", err)
	}
	if got := udpSockoptInt(t, c, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled", got)
	}
}

func TestApplyTCPConnOptsAppliesSetsockoptOnUDPUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UDP4:127.0.0.1:9,setsockopt=%d:%d:1", SOLSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGenericSetsockoptToNetConn(c, mustDecodeAddress(t, spec), SockoptPhaseConnected); err != nil {
		t.Fatalf("UDP setsockopt must apply, not no-op: %v", err)
	}
	if got := udpSockoptInt(t, c, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled after ApplyTCPConnOpts on UDP", got)
	}
}

func TestApplySetsockoptKernelRejectedUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	// Classic SETSOCKOPT MSS=1: IPPROTO_TCP + TCP_MAXSEG + 1 is rejected.
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt=%d:%d:1", unix.IPPROTO_TCP, unix.TCP_MAXSEG))
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyGenericSetsockoptToNetConn(cli, mustDecodeAddress(t, spec), SockoptPhaseConnected)
	if err == nil {
		t.Fatal("TCP_MAXSEG=1 must fail the open, not succeed silently")
	}
}

func TestApplyGenericSetsockoptInvalidOptionUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,setsockopt=-1:-1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(c, mustDecodeAddress(t, spec), "udp4"); err == nil {
		t.Fatal("invalid level/opt must fail, not succeed silently")
	}
}

// sockoptFlagOn reports whether a SOL_SOCKET boolean option is enabled.
// Linux returns 1; Darwin returns the so_options bit (SO_KEEPALIVE is 8).
func sockoptFlagOn(v int) bool { return v != 0 }

type netConnUnwrapper struct {
	net.Conn
}

func (c netConnUnwrapper) NetConn() net.Conn { return c.Conn }

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	cli, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv := <-ch
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	t.Cleanup(func() { _ = srv.c.Close() })
	return cli, srv.c.(*net.TCPConn)
}

func tcpSockoptInt(t *testing.T, tc *net.TCPConn, opt int) int {
	t.Helper()
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func udpSockoptInt(t *testing.T, uc *net.UDPConn, opt int) int {
	t.Helper()
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}
