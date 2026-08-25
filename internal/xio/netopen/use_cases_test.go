package netopen

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func echoAccepted(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(c, c)
	}()
}

func TestTCPListenConnectEcho(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	ls, err := parse.ParseSpec("TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := openTCP4Listen(context.Background(), ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if srv.Listener == nil {
		t.Fatal("TCP-LISTEN did not return a listener")
	}
	echoAccepted(t, srv.Listener)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	cs, err := parse.ParseSpec("TCP4:127.0.0.1:" + strconv.Itoa(port) + ",connect-timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	cli, err := openTCP4Connect(context.Background(), cs, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	const payload = "tcp-hello"
	if _, err := io.WriteString(cli.Stream, payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(cli.Stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("TCP echo got %q", buf)
	}
}

func TestUDPRecvfromPktinfo(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork,pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := openUDP4Recvfrom(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if srv.Listener == nil {
		t.Fatal("UDP-RECVFROM did not return a listener")
	}
	addr, ok := srv.Listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("addr %T", srv.Listener.Addr())
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := srv.Listener.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()
	client, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	const payload = "pktinfo-hi"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-accepted:
		t.Cleanup(func() { _ = c.Close() })
		if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(payload))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], []byte(payload)) {
			t.Fatalf("got %q", buf[:n])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UDP-RECVFROM,pktinfo did not accept")
	}
}
