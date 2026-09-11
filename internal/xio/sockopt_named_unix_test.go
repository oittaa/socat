//go:build linux || darwin

package xio

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketOptionsDontrouteOnUDPUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,so-dontroute")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_DONTROUTE); !sockoptFlagOn(got) {
		t.Fatalf("UDP SO_DONTROUTE=%d want enabled", got)
	}
}

func TestApplySocketOptionsRejectsInvalidNamedIntUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, specText := range []string{
		"TCP:127.0.0.1:9,dontroute=no",
	} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplySocketOptions(fd, spec); err == nil {
			t.Fatalf("%s: expected invalid value", specText)
		}
	}
}

func TestListenControlAppliesDontrouteUnix(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,so-dontroute")
	if err != nil {
		t.Fatal(err)
	}
	lc := NewTCPListenConfig(spec)
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if got := listenerSockoptInt(t, ln, unix.SO_DONTROUTE); !sockoptFlagOn(got) {
		t.Fatalf("listener SO_DONTROUTE=%d want enabled", got)
	}
}

func TestApplyTCPConnOptsDoesNotApplyPastSocketNamedUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,so-dontroute")
	if err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, unix.SO_DONTROUTE); got != 0 {
		t.Fatalf("precondition SO_DONTROUTE=%d want 0", got)
	}
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, unix.SO_DONTROUTE); got != 0 {
		t.Fatalf("ApplyTCPConnOpts applied PH_PASTSOCKET so-dontroute: SO_DONTROUTE=%d", got)
	}
}

func TestApplyTCPConnOptsNamedConnectedOnUDPUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,tcp-maxseg-late=512")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyTCPConnOpts(spec, c)
	if err == nil {
		t.Fatal("tcp-maxseg-late on UDP must fail, not no-op")
	}
}

func TestFDRejectsMaxsegLateUnix(t *testing.T) {
	spec, err := parse.ParseSpec("FD:0,tcp-maxseg-late=512")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectGenericSetsockoptPhases(mustDecodeAddress(t, spec), "FD", SockoptPhasePrebind, SockoptPhaseConnected)
	if err == nil || !strings.Contains(err.Error(), "not supported at this lifecycle phase") {
		t.Fatalf("error=%v want CONNECTED phase rejection", err)
	}
}
