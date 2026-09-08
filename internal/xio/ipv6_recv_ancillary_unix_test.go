//go:build linux || darwin

package xio

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

func TestControlMessageBytesTruncated(t *testing.T) {
	oob := []byte{0x01, 0x02, 0x03, 0x04}
	if got := ControlMessageBytes(oob, len(oob), unix.MSG_CTRUNC); got != nil {
		t.Fatalf("MSG_CTRUNC returned %v; truncated ancillary must not be parsed", got)
	}
	got := ControlMessageBytes(oob, 2, 0)
	if !bytes.Equal(got, oob[:2]) {
		t.Fatalf("got %v want %v", got, oob[:2])
	}
	if ControlMessageBytes(oob, 0, 0) != nil {
		t.Fatal("oobn=0 must return nil")
	}
}
