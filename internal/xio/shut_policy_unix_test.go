//go:build unix

package xio

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// udpTestStream is a connected datagram whose default ShutdownWrite is a no-op
// (same as this port's UDP wrappers). It embeds *net.UDPConn so shut-down can
// reach shutdown(2).
type udpTestStream struct{ *net.UDPConn }

func (u udpTestStream) ShutdownWrite() error { return nil }

func TestShutPolicyDatagramEndpoints(t *testing.T) {
	tests := []struct {
		opt   string
		check func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream)
	}{
		{
			opt: "shut-none",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := wrapped.Write([]byte("still-open")); err != nil {
					t.Fatalf("write after shut-none: %v", err)
				}
			},
		},
		{
			opt: "shut-down",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := wrapped.Write([]byte("after-down")); err == nil {
					t.Fatal("write after shut-down succeeded")
				}
			},
		},
		{
			opt: "shut-close",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := local.Write([]byte("after-close")); err == nil {
					t.Fatal("Write after shut-close succeeded")
				}
			},
		},
		{
			opt: "shut-null",
			check: func(t *testing.T, local, peer *net.UDPConn, wrapped relay.Stream) {
				_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
				done := make(chan []byte, 1)
				go func() {
					buf := make([]byte, 16)
					n, _, err := peer.ReadFromUDP(buf)
					if err != nil {
						done <- []byte("err:" + err.Error())
						return
					}
					done <- buf[:n]
				}()
				if err := wrapped.ShutdownWrite(); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-done:
					if string(got) != "" {
						t.Fatalf("peer got %q want empty datagram", got)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for shut-null datagram")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.opt, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			local, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, peer.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = local.Close() }()
			spec, err := parse.ParseSpec("UDP-DATAGRAM:127.0.0.1:9," + tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := WrapCommon(spec, udpTestStream{UDPConn: local})
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, local, peer, wrapped)
		})
	}
}

func TestShutDownOnStreamSocketpair(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	local := os.NewFile(uintptr(fds[0]), "local")
	peer := os.NewFile(uintptr(fds[1]), "peer")
	defer func() { _ = local.Close() }()
	defer func() { _ = peer.Close() }()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))

	spec, err := parse.ParseSpec("SOCKETPAIR,shut-down")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := WrapCommon(spec, FileStream(local))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := io.ReadFull(peer, buf[:2])
	if err != nil || n != 2 || string(buf[:2]) != "hi" {
		t.Fatalf("peer read n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = peer.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("after shut-down peer Read n=%d err=%v want EOF", n, err)
	}
}
