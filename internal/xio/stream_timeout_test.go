package xio

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestWrapCommonReceiveTimeoutBoundsRead(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	spec, err := parse.ParseSpec("TCP:localhost:1,rcvtimeo=0.03")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := WrapCommon(spec, relay.NetStream{Conn: client})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = stream.Read(make([]byte, 1))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read error=%v want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("receive timeout took %s", elapsed)
	}
}

func TestWrapCommonSendTimeoutBoundsWrite(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	spec, err := parse.ParseSpec("TCP:localhost:1,sndtimeo=0.03")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := WrapCommon(spec, relay.NetStream{Conn: client})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = stream.Write([]byte("blocked"))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("write error=%v want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("send timeout took %s", elapsed)
	}
}
