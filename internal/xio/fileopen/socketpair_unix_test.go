//go:build linux || darwin

package fileopen

import (
	"bytes"
	"context"
	"errors"
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
	o, err := openSocketpair(context.Background(), parse.Spec{Type: "SOCKETPAIR"}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if got := streamSOType(t, o.Stream); got != syscall.SOCK_DGRAM {
		t.Fatalf("default SO_TYPE=%d want SOCK_DGRAM", got)
	}

	first := bytes.Repeat([]byte("a"), 20)
	second := bytes.Repeat([]byte("b"), 20)
	if _, err := o.Stream.Write(first); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Stream.Write(second); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 24)
	n, err := o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 20 || !bytes.Equal(buf[:n], first) {
		t.Fatalf("first datagram n=%d %q want 20-byte packet", n, buf[:n])
	}
	n, err = o.Stream.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 20 || !bytes.Equal(buf[:n], second) {
		t.Fatalf("second datagram n=%d %q want 20-byte packet", n, buf[:n])
	}
}

func TestSocketpairExplicitStreamType(t *testing.T) {
	o, err := openSocketpair(context.Background(), parse.Spec{
		Type:    "SOCKETPAIR",
		Options: []parse.Option{{Name: "socktype", Value: strconv.Itoa(syscall.SOCK_STREAM), Has: true}},
	}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if got := streamSOType(t, o.Stream); got != syscall.SOCK_STREAM {
		t.Fatalf("explicit socktype SO_TYPE=%d want SOCK_STREAM", got)
	}
	if _, err := o.Stream.Write([]byte("aaaa")); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Stream.Write([]byte("bbbb")); err != nil {
		t.Fatal(err)
	}
	var got []byte
	buf := make([]byte, 8)
	deadline := time.Now().Add(2 * time.Second)
	for len(got) < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("stream read %q want aaaabbbb", got)
		}
		n, err := o.Stream.Read(buf)
		if err != nil {
			t.Fatalf("stream read: %v (got %q)", err, got)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != "aaaabbbb" {
		t.Fatalf("stream read %q want aaaabbbb", got)
	}
}

func streamSOType(t *testing.T, st relay.Stream) int {
	t.Helper()
	var conn syscall.Conn
	var walk func(any, int)
	walk = func(v any, depth int) {
		if conn != nil || v == nil || depth > 16 {
			return
		}
		if c, ok := v.(syscall.Conn); ok {
			conn = c
			return
		}
		switch x := v.(type) {
		case relay.FDStream:
			walk(x.R, depth+1)
			if conn == nil {
				walk(x.W, depth+1)
			}
		case relay.NetStream:
			walk(x.Conn, depth+1)
		default:
			if u, ok := v.(interface{ UnwrapStream() relay.Stream }); ok {
				walk(u.UnwrapStream(), depth+1)
			}
		}
	}
	walk(st, 0)
	if conn == nil {
		t.Fatalf("no syscall.Conn on %T", st)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var typ int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		typ, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	return typ
}

func TestSocketpairDatagramEchoThroughTransfer(t *testing.T) {
	pair, err := openSocketpair(context.Background(), parse.Spec{
		Type: "SOCKETPAIR",
		Options: []parse.Option{
			{Name: "rcvtimeo", Value: "0.02", Has: true},
			{Name: "sndtimeo", Value: "0.02", Has: true},
		},
	}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pair.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close socketpair: %v", err)
		}
	})

	srvPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cliPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := srvPC.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close server packet connection: %v", err)
		}
	})
	t.Cleanup(func() {
		if err := cliPC.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close client packet connection: %v", err)
		}
	})
	srv := srvPC.(*net.UDPConn)
	cli := cliPC.(*net.UDPConn)
	udp := udpEchoConn{UDPConn: srv, peer: cli.LocalAddr().(*net.UDPAddr)}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- relay.Transfer(ctx, udp, pair.Stream, relay.Config{BufferSize: 8192, Linger: 200 * time.Millisecond})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("transfer: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("transfer did not stop after cancellation")
		}
	})

	first := []byte("aaaaaaaaaaaaaaaaaaaa")
	second := []byte("bbbbbbbbbbbbbbbbbb")
	// Leave the socketpair idle across several configured timeout intervals;
	// the relay must remain live and preserve datagram boundaries.
	time.Sleep(80 * time.Millisecond)
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
