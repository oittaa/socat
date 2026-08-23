package xio

import (
	"io"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

type closeCountingStream struct{ closes int }

func (*closeCountingStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (*closeCountingStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *closeCountingStream) Close() error {
	s.closes++
	return nil
}
func (*closeCountingStream) ShutdownWrite() error { return nil }

func TestShutCloseFullyClosesOnce(t *testing.T) {
	inner := &closeCountingStream{}
	stream, err := WrapCommon(parse.Spec{Options: []parse.Option{{Name: "shut-close"}}}, inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.closes != 1 {
		t.Fatalf("Close calls=%d want 1", inner.closes)
	}
}
