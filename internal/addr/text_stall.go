package addr

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// TEXT:<string> — input is the string (with classic escapes); output goes to stdout.
func openTEXT(_ context.Context, s parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("TEXT requires string parameter")
	}
	// Escapes already expanded by the address parser (quotes / backslash).
	raw := strings.Join(s.Params, ":")
	data := []byte(raw)
	r := bytes.NewReader(data)
	var stream relay.Stream
	switch mode {
	case ModeRead:
		stream = relay.FDStream{R: r, W: discardWriter{}, C: nopCloser{}}
	case ModeWrite:
		stream = relay.FDStream{R: eofReader{}, W: os.Stdout, C: nopCloser{}}
	default:
		stream = relay.FDStream{
			R: r,
			W: os.Stdout,
			C: nopCloser{},
		}
	}
	st, err := wrapCommon(s, stream)
	if err != nil {
		return nil, err
	}
	return &Opened{Stream: st, Label: "TEXT"}, nil
}

// STALL — never readable, never writable until closed.
// Close unblocks I/O so -T idle timeout / SIGTERM can finish the process.
func openSTALL(_ context.Context, _ parse.Spec, _ Mode, _ *Global) (*Opened, error) {
	return &Opened{
		Stream: newStallStream(),
		Label:  "STALL",
	}, nil
}

type stallStream struct {
	done chan struct{}
	once sync.Once
}

func newStallStream() *stallStream {
	return &stallStream{done: make(chan struct{})}
}

func (s *stallStream) Read([]byte) (int, error) {
	<-s.done
	return 0, io.EOF
}

func (s *stallStream) Write([]byte) (int, error) {
	<-s.done
	return 0, io.ErrClosedPipe
}

func (s *stallStream) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *stallStream) ShutdownWrite() error {
	return s.Close()
}

// expandEscapes handles common classic socat string escapes.
func expandEscapes(s string) []byte {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '0':
			b.WriteByte(0)
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 < len(s) {
				var v byte
				fmt.Sscanf(s[i+1:i+3], "%02x", &v)
				b.WriteByte(v)
				i += 2
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return []byte(b.String())
}

