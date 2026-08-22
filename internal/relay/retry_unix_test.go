//go:build unix

package relay

import (
	"bytes"
	"context"
	"io"
	"testing"

	"golang.org/x/sys/unix"
)

type eagainTestStream struct {
	input     []byte
	readCalls int
	output    bytes.Buffer
}

func (s *eagainTestStream) Read(p []byte) (int, error) {
	s.readCalls++
	switch s.readCalls {
	case 1:
		return 0, unix.EAGAIN
	case 2:
		return copy(p, s.input), nil
	default:
		return 0, io.EOF
	}
}

func (s *eagainTestStream) Write(p []byte) (int, error) { return s.output.Write(p) }
func (s *eagainTestStream) Close() error                { return nil }
func (s *eagainTestStream) ShutdownWrite() error        { return nil }

func TestTransferRetriesUnixEAGAIN(t *testing.T) {
	source := &eagainTestStream{input: []byte("after-eagain")}
	destination := &eagainTestStream{}

	if err := Transfer(context.Background(), source, destination, Config{LeftToRight: true}); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if got := destination.output.String(); got != "after-eagain" {
		t.Fatalf("received %q, want after-eagain", got)
	}
	if source.readCalls != 3 {
		t.Fatalf("Read calls = %d, want 3", source.readCalls)
	}
}
