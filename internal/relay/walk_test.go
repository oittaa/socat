package relay

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"
)

type walkTestWrapper struct {
	Stream
}

func (w *walkTestWrapper) UnwrapStream() Stream         { return w.Stream }
func (w *walkTestWrapper) UnwrapZeroCopyStream() Stream { return w.Stream }

type deadlineTestStream struct {
	readDeadlineCalls  int
	writeDeadlineCalls int
}

func (*deadlineTestStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (*deadlineTestStream) Write(p []byte) (int, error) { return len(p), nil }
func (*deadlineTestStream) Close() error                { return nil }
func (*deadlineTestStream) ShutdownWrite() error        { return nil }
func (s *deadlineTestStream) SetReadDeadline(time.Time) error {
	s.readDeadlineCalls++
	return nil
}
func (s *deadlineTestStream) SetWriteDeadline(time.Time) error {
	s.writeDeadlineCalls++
	return nil
}

func wrapTestStream(stream Stream, depth int) Stream {
	for range depth {
		stream = &walkTestWrapper{Stream: stream}
	}
	return stream
}

func TestCapabilityWalkerTraversesDeepWrappers(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close endpoint: %v", err)
		}
	})

	wrapped := wrapTestStream(FDStream{R: file, W: file, C: file}, 32)
	wantFD := int(file.Fd())
	if got := streamReadFD(wrapped); got != wantFD {
		t.Fatalf("read fd=%d want %d", got, wantFD)
	}
	if got := streamWriteFD(wrapped); got != wantFD {
		t.Fatalf("write fd=%d want %d", got, wantFD)
	}
	if _, ok := unwrapZeroCopyReader(wrapped); !ok {
		t.Fatal("deeply wrapped zero-copy reader was not discovered")
	}
	if _, ok := unwrapZeroCopyWriter(wrapped); !ok {
		t.Fatal("deeply wrapped zero-copy writer was not discovered")
	}

	deadlineStream := &deadlineTestStream{}
	deadlineWrapped := wrapTestStream(deadlineStream, 32)
	setStreamReadDeadline(deadlineWrapped, time.Now())
	if !setStreamWriteDeadline(deadlineWrapped, time.Now()) {
		t.Fatal("deeply wrapped write deadline was not discovered")
	}
	if deadlineStream.readDeadlineCalls != 1 || deadlineStream.writeDeadlineCalls != 1 {
		t.Fatalf("deadline calls=(%d,%d), want (1,1)", deadlineStream.readDeadlineCalls, deadlineStream.writeDeadlineCalls)
	}
}

func TestCapabilityWalkerKeepsFDDirectionsSeparate(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "writer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close writer: %v", err)
		}
	})

	stream := FDStream{R: bytes.NewReader(nil), W: file, C: file}
	if got := streamReadFD(stream); got != -1 {
		t.Fatalf("read fd=%d, unexpectedly used the write endpoint", got)
	}
	if got := streamWriteFD(stream); got != int(file.Fd()) {
		t.Fatalf("write fd=%d want %d", got, file.Fd())
	}
}

func TestCapabilityWalkerDetectsWrapperCycles(t *testing.T) {
	left := &walkTestWrapper{}
	right := &walkTestWrapper{}
	left.Stream = right
	right.Stream = left

	if got := streamReadFD(left); got != -1 {
		t.Fatalf("cyclic stream fd=%d want -1", got)
	}
	if streamNeedsExplicitPoll(left) {
		t.Fatal("cyclic stream unexpectedly requires explicit polling")
	}
	if _, ok := unwrapZeroCopyReader(left); ok {
		t.Fatal("cyclic stream unexpectedly supports zero-copy")
	}
	setStreamReadDeadline(left, time.Now())
	if setStreamWriteDeadline(left, time.Now()) {
		t.Fatal("cyclic stream unexpectedly supports write deadlines")
	}
}

func TestCapabilityWalkerFindsDeepPollEndpoint(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("close pipe reader: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Errorf("close pipe writer: %v", err)
		}
	})

	wrapped := wrapTestStream(FDStream{R: reader, W: writer, C: reader}, 32)
	if !streamNeedsExplicitPoll(wrapped) {
		t.Fatal("deeply wrapped pipe did not enable explicit polling")
	}
}
