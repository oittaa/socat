//go:build linux || darwin

package dtlsopen

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestPacketizerExecStream(t *testing.T) {
	ctx, client, peer := packetEndpointPair(t, "")
	right, err := parse.ParseChannel("EXEC:cat")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- xio.RunOpened(ctx, client, right, &xio.Global{Linger: time.Second}) }()
	data := bytes.Repeat([]byte{'x'}, 9000)
	if _, err := peer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := peer.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var got []byte
	buffer := make([]byte, 16384)
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
		t.Fatalf("EXEC echo: %d/%d bytes", len(got), len(data))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPacketizerExecNoforkStillRejectsDTLS(t *testing.T) {
	ctx, client, _ := packetEndpointPair(t, "")
	right, err := parse.ParseChannel("EXEC:cat,nofork")
	if err != nil {
		t.Fatal(err)
	}
	if err := xio.RunOpened(ctx, client, right, &xio.Global{}); err == nil {
		t.Fatal("nofork accepted an endpoint without a plaintext descriptor")
	}
}
