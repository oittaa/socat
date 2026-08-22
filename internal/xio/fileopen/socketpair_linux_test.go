//go:build linux

package fileopen

import (
	"bytes"
	"context"
	"strconv"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketpairSeqpacketKeepsBoundaries(t *testing.T) {
	o, err := openSocketpair(context.Background(), parse.Spec{
		Type:    "SOCKETPAIR",
		Options: []parse.Option{{Name: "socktype", Value: strconv.Itoa(syscall.SOCK_SEQPACKET), Has: true}},
	}, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := o.Stream.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Stream.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := o.Stream.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("one")) {
		t.Fatalf("first=%q err=%v", buf[:n], err)
	}
	n, err = o.Stream.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("two")) {
		t.Fatalf("second=%q err=%v", buf[:n], err)
	}
}
