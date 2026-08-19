//go:build unix

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func TestUnixSeqpacketUsesKernelSocketType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seqpacket.sock")
	socktype := strconv.Itoa(syscall.SOCK_SEQPACKET)
	server, err := openUnixListen(context.Background(), parse.Spec{
		Type:   "UNIX-LISTEN",
		Params: []string{path},
		Options: []parse.Option{
			{Name: "so-type", Value: socktype, Has: true},
			{Name: "fork"},
		},
	}, xio.ModeRDWR, nil)
	if err != nil {
		if errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("SOCK_SEQPACKET is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	if got := socketType(t, server.Listener); got != syscall.SOCK_SEQPACKET {
		t.Fatalf("listener SO_TYPE=%d want SOCK_SEQPACKET=%d", got, syscall.SOCK_SEQPACKET)
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := server.Listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := openUnixConnect(context.Background(), parse.Spec{
		Type:    "UNIX-CONNECT",
		Params:  []string{path},
		Options: []parse.Option{{Name: "socktype", Value: socktype, Has: true}},
	}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	var peer net.Conn
	select {
	case peer = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out accepting seqpacket connection")
	}
	defer func() { _ = peer.Close() }()

	netStream, ok := client.Stream.(relay.NetStream)
	if !ok {
		t.Fatalf("client stream type %T want relay.NetStream", client.Stream)
	}
	if got := socketType(t, netStream.Conn); got != syscall.SOCK_SEQPACKET {
		t.Fatalf("client SO_TYPE=%d want SOCK_SEQPACKET=%d", got, syscall.SOCK_SEQPACKET)
	}

	payload := []byte("real seqpacket\n")
	if _, err := client.Stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload=%q want %q", got, payload)
	}
}

func TestExplicitUnixSocketTypeMismatchesFail(t *testing.T) {
	seqpacket := strconv.Itoa(syscall.SOCK_SEQPACKET)
	tests := []struct {
		name       string
		listen     func(t *testing.T, path string) io.Closer
		clientOpts []parse.Option
	}{
		{name: "CONNECT_TO_DGRAM", listen: listenUnixgram},
		{name: "CONNECT_TO_SEQPACKET", listen: listenUnixpacket},
		{name: "SEQPACKET_TO_STREAM", listen: listenUnixStream, clientOpts: []parse.Option{{Name: "socktype", Value: seqpacket, Has: true}}},
		{name: "SEQPACKET_TO_DGRAM", listen: listenUnixgram, clientOpts: []parse.Option{{Name: "socktype", Value: seqpacket, Has: true}}},
		{name: "DGRAM_TO_STREAM", listen: listenUnixStream, clientOpts: []parse.Option{{Name: "socktype", Value: strconv.Itoa(syscall.SOCK_DGRAM), Has: true}}},
		{name: "DGRAM_TO_SEQPACKET", listen: listenUnixpacket, clientOpts: []parse.Option{{Name: "socktype", Value: strconv.Itoa(syscall.SOCK_DGRAM), Has: true}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "target.sock")
			listener := tt.listen(t, path)
			defer func() { _ = listener.Close() }()

			o, err := openUnixConnect(context.Background(), parse.Spec{
				Type:    "UNIX-CONNECT",
				Params:  []string{path},
				Options: tt.clientOpts,
			}, xio.ModeRDWR, nil)
			if err == nil {
				_ = o.Close()
				t.Fatal("incompatible UNIX socket types unexpectedly connected")
			}
		})
	}
}

func TestGenericUnixAutodetectsSocketType(t *testing.T) {
	tests := []struct {
		name   string
		listen func(t *testing.T, path string) io.Closer
		want   int
	}{
		{name: "dgram", listen: listenUnixgram, want: syscall.SOCK_DGRAM},
		{name: "seqpacket", listen: listenUnixpacket, want: syscall.SOCK_SEQPACKET},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "target.sock")
			listener := tt.listen(t, path)
			defer func() { _ = listener.Close() }()

			o, err := openUnixConnect(context.Background(), parse.Spec{
				Type:   "UNIX",
				Params: []string{path},
			}, xio.ModeRDWR, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = o.Close() }()
			netStream, ok := o.Stream.(relay.NetStream)
			if !ok {
				t.Fatalf("stream type %T want relay.NetStream", o.Stream)
			}
			if got := socketType(t, netStream.Conn); got != tt.want {
				t.Fatalf("SO_TYPE=%d want %d", got, tt.want)
			}
		})
	}
}

func socketType(t *testing.T, conn any) int {
	t.Helper()
	sc, ok := conn.(syscall.Conn)
	if !ok {
		t.Fatalf("%T does not implement syscall.Conn", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		got, socketErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return got
}

func listenUnixStream(t *testing.T, path string) io.Closer {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func listenUnixpacket(t *testing.T, path string) io.Closer {
	t.Helper()
	listener, err := net.Listen("unixpacket", path)
	if err != nil {
		if errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("SOCK_SEQPACKET is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return listener
}

func listenUnixgram(t *testing.T, path string) io.Closer {
	t.Helper()
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}
