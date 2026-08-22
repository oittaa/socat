package xio

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// eofThenAppendReader returns EOF until flag flips, then serves the payload
// once (simulates a file another process appends to).
type eofThenAppendReader struct {
	mu   sync.Mutex
	data []byte
	pos  int
}

func (r *eofThenAppendReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *eofThenAppendReader) append(b []byte) {
	r.mu.Lock()
	r.data = append(r.data, b...)
	r.mu.Unlock()
}

func TestWrapCommonIgnoreEOFKeepsServingAfterEOF(t *testing.T) {
	src := &eofThenAppendReader{data: []byte("first")}
	spec, err := parse.ParseSpec("PIPE,ignoreeof")
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	stream, err := WrapCommon(spec, relay.FDStream{
		R:      src,
		W:      io.Discard,
		C:      nopCloser{},
		CloseW: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for len(got) < len("first")+len("second") {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}
			got = append(got, buf[:n]...)
		}
	}()
	time.Sleep(120 * time.Millisecond) // let EOF be hit and retried
	src.append([]byte("second"))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ignoreeof transfer stalled after EOF")
	}
	_ = stream.Close()
	if string(got) != "firstsecond" {
		t.Fatalf("got %q", got)
	}
}

type nopCloser struct{}

func (nopCloser) Close() error         { return nil }
func (nopCloser) ShutdownWrite() error { return nil }
