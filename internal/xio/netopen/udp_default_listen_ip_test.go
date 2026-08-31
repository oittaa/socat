package netopen

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPNetworkWithListenDefaultPrecedence(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")

	if got := udpNetworkWithListenDefault(&xio.Global{}, parse.Spec{}); got != "udp6" {
		t.Fatalf("environment: got %q want udp6", got)
	}
	if got := udpNetworkWithListenDefault(&xio.Global{IPVersion: xio.IPv4}, parse.Spec{}); got != "udp4" {
		t.Fatalf("global: got %q want udp4", got)
	}
	s := parse.Spec{Options: []parse.Option{{Name: "pf", Value: "ip4", Has: true}}}
	if got := udpNetworkWithListenDefault(&xio.Global{IPVersion: xio.IPv6}, s); got != "udp4" {
		t.Fatalf("pf: got %q want udp4", got)
	}
}

func TestUDPDatagramHonorsDefaultListenIP6(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")

	recv, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { _ = recv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	s, err := parse.ParseSpec("UDP-DATAGRAM:[::1]:" + strconv.Itoa(recv.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDPDatagram(ctx, s, xio.ModeWrite, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	if _, err := o.Stream.Write([]byte("udp6")); err != nil {
		t.Fatal(err)
	}
	if err := recv.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if n, _, err := recv.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	} else if got := string(buf[:n]); got != "udp6" {
		t.Fatalf("payload=%q want udp6", got)
	}
}

func TestNetworkUDPIgnoresDefaultListenIP6(t *testing.T) {
	t.Setenv("SOCAT_DEFAULT_LISTEN_IP", "6")
	if got := NetworkUDP(&xio.Global{}, parse.Spec{}, "udp4"); got != "udp4" {
		t.Fatalf("got %q want udp4", got)
	}
}
