//go:build linux

package relay

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

func TestPrepareZeroCopyEndpointMatrix(t *testing.T) {
	file := openPayloadFile(t, []byte("payload"))
	src := FDStream{R: file, W: file, C: file}

	t.Run("TCP stream", func(t *testing.T) {
		client, server := tcpPair(t)
		defer func() { _ = client.Close() }()
		defer func() { _ = server.Close() }()
		plan := prepareZeroCopy(src, NetStream{Conn: client})
		if plan == nil {
			t.Fatal("regular file to TCP should have a Linux zero-copy plan")
		}
		_ = plan.Close()
	})

	t.Run("UNIX stream", func(t *testing.T) {
		client, server := unixStreamPair(t, "unix")
		defer func() { _ = client.Close() }()
		defer func() { _ = server.Close() }()
		plan := prepareZeroCopy(src, NetStream{Conn: client})
		if plan == nil {
			t.Fatal("regular file to UNIX stream should have a Linux zero-copy plan")
		}
		_ = plan.Close()
	})

	t.Run("UNIX datagram", func(t *testing.T) {
		path := testutil.UnixSocketPath(t, "socket")
		server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = server.Close() }()
		client, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		if plan := prepareZeroCopy(src, NetStream{Conn: client}); plan != nil {
			_ = plan.Close()
			t.Fatal("UNIX datagram must retain configured-buffer packetization")
		}
	})

	t.Run("UNIX seqpacket", func(t *testing.T) {
		client, server := unixStreamPair(t, "unixpacket")
		defer func() { _ = client.Close() }()
		defer func() { _ = server.Close() }()
		if plan := prepareZeroCopy(src, NetStream{Conn: client}); plan != nil {
			_ = plan.Close()
			t.Fatal("UNIX seqpacket must retain configured-buffer packetization")
		}
	})
}

func TestRecordUnixSocketsPreserveConfiguredBlocks(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789"), 2000) // 20,000 bytes

	t.Run("datagram", func(t *testing.T) {
		path := testutil.UnixSocketPath(t, "socket")
		server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = server.Close() }()
		client, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		transferFileToRecordConn(t, payload, client, server)
	})

	t.Run("seqpacket", func(t *testing.T) {
		client, server := unixStreamPair(t, "unixpacket")
		defer func() { _ = server.Close() }()
		transferFileToRecordConn(t, payload, client, server)
	})
}

func TestZeroCopyProgressPreservesIdleAndLiveStats(t *testing.T) {
	client, server := tcpPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	outPath := filepath.Join(t.TempDir(), "output")
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	tracker := &Tracker{}
	transferDone := make(chan error, 1)
	go func() {
		transferDone <- Transfer(context.Background(), NetStream{Conn: server}, FDStream{
			R: out, W: out, C: out, CloseW: func() error { return nil },
		}, Config{
			BufferSize: 8192,
			// Generous margin over the 30ms writer cadence: on loaded or
			// slower runners a single scheduling gap must not trip the idle
			// watcher and silently truncate the transfer mid-stream.
			IdleTimeout: 600 * time.Millisecond,
			LeftToRight: true,
			Tracker:     tracker,
		})
	}()

	const writes = 20
	chunk := []byte("1234567890")
	fiveSent := make(chan struct{})
	go func() {
		for i := 0; i < writes; i++ {
			_, _ = client.Write(chunk)
			if i == 4 {
				close(fiveSent)
			}
			time.Sleep(30 * time.Millisecond)
		}
		_ = client.(*net.TCPConn).CloseWrite()
	}()

	select {
	case <-fiveSent:
	case <-time.After(2 * time.Second):
		t.Fatal("sender stalled")
	}
	deadline := time.Now().Add(time.Second)
	for tracker.Snapshot().BytesLR == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := tracker.Snapshot().BytesLR; got == 0 {
		t.Fatal("live statistics did not observe zero-copy progress")
	}

	select {
	case err := <-transferDone:
		if err != nil {
			t.Fatalf("Transfer failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("transfer did not finish")
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat(chunk, writes)
	if !bytes.Equal(got, want) {
		t.Fatalf("active transfer wrote %d bytes, want %d", len(got), len(want))
	}
	stats := tracker.Snapshot()
	if stats.BytesLR != uint64(len(want)) {
		t.Fatalf("stats bytes = %d, want %d", stats.BytesLR, len(want))
	}
	if stats.BlocksLR < 2 {
		t.Fatalf("stats blocks = %d, want progress from multiple reads", stats.BlocksLR)
	}
}

func transferFileToRecordConn(t *testing.T, payload []byte, client, server net.Conn) {
	t.Helper()
	file := openPayloadFile(t, payload)
	defer func() { _ = file.Close() }()

	received := make(chan []byte, 1)
	go func() {
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8192)
		got := make([]byte, 0, len(payload))
		for len(got) < len(payload) {
			n, err := server.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		received <- got
	}()

	var stats Stats
	err := Transfer(context.Background(), FDStream{
		R: file, W: file, C: file, CloseW: func() error { return nil },
	}, NetStream{Conn: client}, Config{
		BufferSize:  8192,
		LeftToRight: true,
		OnStats: func(s Stats) {
			stats = s
		},
	})
	if err != nil {
		t.Fatalf("Transfer failed: %v", err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatalf("received %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("receiver timed out")
	}
	if stats.BlocksLR != 3 {
		t.Fatalf("stats blocks = %d, want 3 configured-buffer records", stats.BlocksLR)
	}
}

func openPayloadFile(t *testing.T, payload []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	return client, server
}

func unixStreamPair(t *testing.T, network string) (net.Conn, net.Conn) {
	t.Helper()
	path := testutil.UnixSocketPath(t, "socket")
	ln, err := net.Listen(network, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	client, err := net.Dial(network, path)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	return client, server
}
