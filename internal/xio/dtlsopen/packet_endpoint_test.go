package dtlsopen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/netopen"
)

func packetEndpointPair(t *testing.T, options string) (context.Context, *xio.Opened, net.Conn) {
	t.Helper()
	server, client := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	// Allow full-size records even with a smaller default socket send buffer.
	ln, err := xio.OpenSpec(ctx, spec(t, "DTLS-LISTEN:0,bind=127.0.0.1,fork,dtls-mtu=20000,sndbuf=65536"+server), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c, err := xio.OpenSpec(ctx, spec(t, "DTLS:"+ln.Listener.Addr().String()+client+options), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	p, err := ln.Listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); _ = p.Close() })
	t.Cleanup(func() { stop() })
	return ctx, c, p
}

func TestPacketizerEndpointLargeRecordToFile(t *testing.T) {
	for _, block := range []int{0, 73} {
		t.Run(fmt.Sprint(block), func(t *testing.T) {
			ctx, client, peer := packetEndpointPair(t, ",dtls-mtu=600,readbytes=16384")
			path := filepath.Join(t.TempDir(), "output")
			right, err := parse.ParseChannel("CREAT:" + path)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- xio.RunOpened(ctx, client, right, &xio.Global{LeftToRight: true, BlockSize: block}) }()
			data := bytes.Repeat([]byte("0123456789abcdef"), 1024)
			if _, err := peer.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("large record: got %d/%d bytes, %v", len(got), len(data), err)
			}
		})
	}
}

func TestPacketizerEndpointUDPBoundaries(t *testing.T) {
	for _, size := range []int{200, 2000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			ctx, client, peer := packetEndpointPair(t, "")
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = udp.Close() }()
			sender, err := net.DialUDP("udp4", nil, udp.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sender.Close() }()
			left := xio.WrapMessageEOF(relay.NetStream{Conn: udp})
			// Keep the connection writable for the marker after the transfer ends.
			right := relay.FDStream{R: client.Stream, W: client.Stream}
			relay.ConfigureStreamPair(left, right)
			done := make(chan error, 1)
			go func() { done <- relay.Transfer(ctx, left, right, relay.Config{LeftToRight: true}) }()
			payload := bytes.Repeat([]byte{'x'}, size)
			if _, err := sender.Write(payload); err != nil {
				t.Fatal(err)
			}
			if _, err := sender.Write(nil); err != nil {
				t.Fatal(err)
			}
			transferErr := <-done
			if size == 2000 && !errors.Is(transferErr, dtls13.ErrDatagramTooLarge) || size == 200 && transferErr != nil {
				t.Fatalf("UDP size %d: transfer %v", size, transferErr)
			}
			marker := []byte("after UDP transfer")
			if _, err := client.Stream.Write(marker); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 8192)
			if size == 200 {
				if n, err := peer.Read(buffer); err != nil || !bytes.Equal(buffer[:n], payload) {
					t.Fatalf("fitting UDP: %d, %v", n, err)
				}
			}
			if n, err := peer.Read(buffer); err != nil || !bytes.Equal(buffer[:n], marker) {
				t.Fatalf("unexpected application record before marker: %d, %v", n, err)
			}
		})
	}
}

func TestPacketizerEndpointDualFileAndUDP(t *testing.T) {
	ctx, client, peer := packetEndpointPair(t, "")
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	if err := udp.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "input")
	data := bytes.Repeat([]byte{'s'}, 18000)
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	dual, err := parse.ParseChannel("OPEN:" + source + "!!UDP:" + udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- xio.RunOpened(ctx, client, dual, &xio.Global{Linger: 2 * time.Second}) }()
	buffer := make([]byte, 16384)
	var got []byte
	for {
		n, err := peer.Read(buffer)
		got = append(got, buffer[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("dual file input: %d/%d bytes", len(got), len(data))
	}
	if _, err := peer.Write(bytes.Repeat([]byte{'r'}, 16384)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("marker")); err != nil {
		t.Fatal(err)
	}
	if err := peer.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	n, _, err := udp.ReadFromUDP(buffer)
	if n != 8192 || err != nil || !bytes.Equal(buffer[:n], bytes.Repeat([]byte{'r'}, 8192)) {
		t.Fatalf("datagram short-buffer behavior: %d, %v", n, err)
	}
	n, _, err = udp.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != "marker" {
		t.Fatalf("record tail became another UDP message: %q, %v", buffer[:n], err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPacketizerEndpointReadDeadline(t *testing.T) {
	_, client, _ := packetEndpointPair(t, "")
	relay.ConfigureStreamPair(client.Stream, semanticTestStream{kind: relay.ByteStreamIO})
	if _, err := relay.SetStreamReadDeadline(client.Stream, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Stream.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline: %d, %v", n, err)
	}
}

func TestPacketizerRecvfromForkKeepsDatagrams(t *testing.T) {
	server, client := credentials(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ln, err := xio.OpenSpec(ctx, spec(t, "DTLS-LISTEN:0,bind=127.0.0.1,fork"+server), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	g := &xio.Global{LeftToRight: true, Log: logx.New()}
	udp, err := xio.OpenSpec(ctx, spec(t, "UDP4-RECVFROM:0,bind=127.0.0.1,fork"), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	right, err := parse.ParseChannel("DTLS:" + ln.Listener.Addr().String() + client)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- xio.RunOpened(ctx, udp, right, g) }()
	sender, err := net.Dial("udp4", udp.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	if _, err := sender.Write(bytes.Repeat([]byte{'x'}, 2000)); err != nil {
		t.Fatal(err)
	}
	peer, err := ln.Listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := peer.Read(make([]byte, 8192)); n != 0 || err != io.EOF {
		t.Fatalf("fork bridge split an oversized message: %d, %v", n, err)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
