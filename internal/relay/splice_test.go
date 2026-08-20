package relay

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTransferZeroCopyTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	payload := bytes.Repeat([]byte("zerocopy-tcp-payload-data-chunk\n"), 1024) // 32KB
	done := make(chan []byte, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, len(payload))
		var total []byte
		for len(total) < len(payload) {
			n, err := conn.Read(buf)
			if n > 0 {
				total = append(total, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- total
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	srcPipeR, srcPipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srcPipeR.Close() }()

	go func() {
		_, _ = srcPipeW.Write(payload)
		_ = srcPipeW.Close()
	}()

	var stats Stats
	cfg := Config{
		BufferSize:  8192,
		LeftToRight: true,
		RightToLeft: false,
		OnStats: func(s Stats) {
			stats = s
		},
	}

	left := FDStream{R: srcPipeR, W: srcPipeR, C: srcPipeR, CloseW: func() error { return nil }}
	right := NetStream{Conn: client}

	if err := Transfer(context.Background(), left, right, cfg); err != nil {
		t.Fatalf("Transfer failed: %v", err)
	}

	select {
	case got := <-done:
		if !bytes.Equal(got, payload) {
			t.Fatalf("received %d bytes, want %d bytes", len(got), len(payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for TCP receiver")
	}

	if stats.BytesLR != uint64(len(payload)) {
		t.Fatalf("stats.BytesLR = %d, want %d", stats.BytesLR, len(payload))
	}
}

func TestTransferZeroCopyFileToTCP(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "input.dat")
	payload := bytes.Repeat([]byte("0123456789abcdef"), 2048) // 32KB
	if err := os.WriteFile(inPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var total []byte
		buf := make([]byte, 4096)
		for len(total) < len(payload) {
			n, err := conn.Read(buf)
			if n > 0 {
				total = append(total, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- total
	}()

	inFile, err := os.Open(inPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inFile.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	left := FDStream{R: inFile, W: inFile, C: inFile, CloseW: func() error { return nil }}
	right := NetStream{Conn: client}

	var stats Stats
	cfg := Config{
		BufferSize:  8192,
		LeftToRight: true,
		RightToLeft: false,
		OnStats: func(s Stats) {
			stats = s
		},
	}

	if err := Transfer(context.Background(), left, right, cfg); err != nil {
		t.Fatalf("Transfer failed: %v", err)
	}

	select {
	case got := <-done:
		if !bytes.Equal(got, payload) {
			t.Fatalf("got %d bytes, want %d bytes", len(got), len(payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for TCP receiver")
	}

	if stats.BytesLR != uint64(len(payload)) {
		t.Fatalf("stats.BytesLR = %d, want %d", stats.BytesLR, len(payload))
	}
}
