//go:build unix

package fileopen

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketpairDatagramKeepsBoundaries(t *testing.T) {
	o, err := openSocketpair(context.Background(), parse.Spec{
		Type:    "SOCKETPAIR",
		Options: []parse.Option{{Name: "socktype", Value: strconv.Itoa(syscall.SOCK_DGRAM), Has: true}},
	}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()

	first := []byte("aaaaaaaaaaaaaaaaaaaa")
	second := []byte("bbbbbbbbbbbbbbbbbb")
	if _, err := o.Stream.Write(first); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Stream.Write(second); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], first) {
		t.Fatalf("first datagram %q want %q", buf[:n], first)
	}
	n, err = o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], second) {
		t.Fatalf("second datagram %q want %q", buf[:n], second)
	}
}

func TestSocketpairStreamMayCoalesce(t *testing.T) {
	o, err := openSocketpair(context.Background(), parse.Spec{Type: "SOCKETPAIR"}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := o.Stream.Write([]byte("aaaa")); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Stream.Write([]byte("bbbb")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 || string(buf[:n]) != "aaaabbbb" {
		t.Fatalf("stream read %q (n=%d) want coalesced aaaabbbb", buf[:n], n)
	}
}

func TestSocketpairDatagramEchoThroughTransfer(t *testing.T) {
	pair, err := openSocketpair(context.Background(), parse.Spec{
		Type:    "SOCKETPAIR",
		Options: []parse.Option{{Name: "socktype", Value: strconv.Itoa(syscall.SOCK_DGRAM), Has: true}},
	}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()

	srvPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cliPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvPC.Close()
	defer cliPC.Close()
	srv := srvPC.(*net.UDPConn)
	cli := cliPC.(*net.UDPConn)
	udp := udpEchoConn{UDPConn: srv, peer: cli.LocalAddr().(*net.UDPAddr)}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_ = relay.Transfer(ctx, udp, pair.Stream, relay.Config{BufferSize: 8192, Linger: 200 * time.Millisecond})
	}()

	first := []byte("aaaaaaaaaaaaaaaaaaaa")
	second := []byte("bbbbbbbbbbbbbbbbbb")
	if _, err := cli.WriteTo(first, srv.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.WriteTo(second, srv.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if err := cli.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := cli.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], first) {
		t.Fatalf("first echo %q", buf[:n])
	}
	n, _, err = cli.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], second) {
		t.Fatalf("second echo %q", buf[:n])
	}
}

type udpEchoConn struct {
	*net.UDPConn
	peer *net.UDPAddr
}

func (u udpEchoConn) Read(p []byte) (int, error) {
	n, _, err := u.ReadFromUDP(p)
	return n, err
}

func (u udpEchoConn) Write(p []byte) (int, error) {
	return u.WriteToUDP(p, u.peer)
}

func (u udpEchoConn) ShutdownWrite() error { return nil }

func TestSocketpairRejectsInvalidSocktype(t *testing.T) {
	_, err := openSocketpair(context.Background(), parse.Spec{
		Type:    "SOCKETPAIR",
		Options: []parse.Option{{Name: "socktype", Value: "99", Has: true}},
	}, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error=%v", err)
	}
}
