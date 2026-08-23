package xio

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func timeoutPipeStream(conn net.Conn) relay.Stream {
	ns := relay.NetStream{Conn: conn}
	return relay.FDStream{
		R:      ns,
		W:      ns,
		C:      ns,
		CloseW: ns.ShutdownWrite,
	}
}

func timeoutSource(src io.Reader) relay.Stream {
	return relay.FDStream{
		R:      src,
		W:      io.Discard,
		C:      io.NopCloser(bytes.NewReader(nil)),
		CloseW: func() error { return nil },
	}
}

func timeoutSink(dst io.Writer) relay.Stream {
	return relay.FDStream{
		R:      bytes.NewReader(nil),
		W:      dst,
		C:      io.NopCloser(bytes.NewReader(nil)),
		CloseW: func() error { return nil },
	}
}

func timeoutSpec(name, value string) parse.Spec {
	return parse.Spec{Options: []parse.Option{{Name: name, Value: value, Has: true}}}
}

func TestShutNullPreservesDeadlineCapabilities(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	spec := parse.Spec{Options: []parse.Option{
		{Name: "rcvtimeo", Value: "0.02", Has: true},
		{Name: "sndtimeo", Value: "0.02", Has: true},
		{Name: "shut-null", Value: "1", Has: true},
	}}
	stream, err := WrapCommon(spec, timeoutPipeStream(client))
	if err != nil {
		t.Fatalf("WrapCommon: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	if found, err := relay.SetStreamReadDeadline(stream, deadline); err != nil || !found {
		t.Fatalf("SetStreamReadDeadline found=%v err=%v", found, err)
	}
	if found, err := relay.SetStreamWriteDeadline(stream, deadline); err != nil || !found {
		t.Fatalf("SetStreamWriteDeadline found=%v err=%v", found, err)
	}
}

func TestSocketReceiveTimeoutRetriesThroughTransfer(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	spec := timeoutSpec("rcvtimeo", "0.02")
	left, err := WrapCommon(spec, timeoutPipeStream(client))
	if err != nil {
		t.Fatalf("WrapCommon: %v", err)
	}

	var got bytes.Buffer
	done := make(chan error, 1)
	go func() {
		err := relay.Transfer(context.Background(), left, timeoutSink(&got), relay.Config{
			LeftToRight: true,
		})
		done <- err
	}()

	time.Sleep(80 * time.Millisecond)
	if _, err := server.Write([]byte("after-timeout")); err != nil {
		t.Fatalf("server.Write: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("server.Close: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if got.String() != "after-timeout" {
		t.Fatalf("received %q, want %q", got.String(), "after-timeout")
	}
}

func TestSocketSendTimeoutRetriesThroughTransfer(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	spec := timeoutSpec("sndtimeo", "0.02")
	right, err := WrapCommon(spec, timeoutPipeStream(client))
	if err != nil {
		t.Fatalf("WrapCommon: %v", err)
	}

	payload := bytes.Repeat([]byte("timeout-safe"), 1024)
	done := make(chan error, 1)
	go func() {
		err := relay.Transfer(context.Background(), timeoutSource(bytes.NewReader(payload)), right, relay.Config{
			LeftToRight: true,
		})
		done <- err
	}()

	time.Sleep(80 * time.Millisecond)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("received payload differs from sent payload")
	}
}

func TestSocketReceiveTimeoutDoesNotReplaceIdleTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	spec := timeoutSpec("rcvtimeo", "0.02")
	left, err := WrapCommon(spec, timeoutPipeStream(client))
	if err != nil {
		t.Fatalf("WrapCommon: %v", err)
	}

	start := time.Now()
	err = relay.Transfer(context.Background(), left, timeoutSink(io.Discard), relay.Config{
		LeftToRight: true,
		IdleTimeout: 80 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 60*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("Transfer elapsed %v, want idle timeout near 80ms", elapsed)
	}
}
