package relay

import (
	"bytes"
	"os"
	"testing"
	"time"
)

type walkTestWrapper struct {
	Stream
}

func wrapTestStream(stream Stream, depth int) Stream {
	for range depth {
		stream = &walkTestWrapper{Stream: stream}
	}
	return stream
}

func TestStreamPropsKeepsFDDirectionsSeparate(t *testing.T) {
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

func TestStreamPropsFindsDeepPollEndpoint(t *testing.T) {
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

func TestStreamPropsForwardsDeadlinesThroughWrappers(t *testing.T) {
	inner := &recordingDeadlineStream{}
	wrapped := wrapTestStream(inner, 8)
	setStreamReadDeadline(wrapped, time.Now())
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if inner.readDeadline.IsZero() {
		t.Fatal("wrapped stream lost the read deadline")
	}
}
