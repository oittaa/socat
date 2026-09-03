package xio

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func socketTimeoutConnSpec(options ...parse.Option) parse.Spec {
	return parse.Spec{Options: options}
}

func TestSocketTimeoutConnRetriesReceiveTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	conn, err := NewSocketTimeoutConn(socketTimeoutConnSpec(
		parse.Option{Name: "rcvtimeo", Value: "0.02", Has: true},
	), client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	conn.EnableSocketTimeouts()

	got := make([]byte, 4)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, got)
		done <- err
	}()

	select {
	case <-time.After(35 * time.Millisecond):
	case err := <-done:
		t.Fatalf("ReadFull exited early on timeout: %v", err)
	}
	if _, err := server.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "late" {
		t.Fatalf("received %q, want late", got)
	}
}

func TestSocketTimeoutConnRetriesSendTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	conn, err := NewSocketTimeoutConn(socketTimeoutConnSpec(
		parse.Option{Name: "sndtimeo", Value: "0.02", Has: true},
	), client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	conn.EnableSocketTimeouts()

	payload := bytes.Repeat([]byte("timeout-safe"), 1024)
	done := make(chan error, 1)
	go func() {
		n, err := conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		done <- err
	}()

	select {
	case <-time.After(35 * time.Millisecond):
	case err := <-done:
		t.Fatalf("Write exited early on timeout: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("received payload differs from sent payload")
	}
}

func TestSocketTimeoutConnPreservesExternalDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	conn, err := NewSocketTimeoutConn(socketTimeoutConnSpec(
		parse.Option{Name: "rcvtimeo", Value: "0.01", Has: true},
	), client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	conn.EnableSocketTimeouts()

	start := time.Now()
	if err := conn.SetReadDeadline(start.Add(60 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = conn.Read(make([]byte, 1))
	if !IsTimeoutErr(err) {
		t.Fatalf("Read error = %v, want timeout", err)
	}
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("Read elapsed %v, want external deadline near 60ms", elapsed)
	}
}
