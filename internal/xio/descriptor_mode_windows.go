//go:build windows

package xio

import (
	"bufio"
	"fmt"
	"io"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func hasPlatformFDLifecycleOptions(s parse.Spec) bool {
	return s.HasOption("noinherit")
}

func descriptorTextModes(s parse.Spec) (binary, text bool) {
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "binary":
			binary = optionEnabled(o)
		case "text":
			text = optionEnabled(o)
		}
	}
	return binary, text
}

// ValidateDescriptorModeOptions validates the mutually exclusive Cygwin
// O_BINARY/O_TEXT modes. Omitted values mean true; =0 clears that mode.
func ValidateDescriptorModeOptions(s parse.Spec) error {
	binary, text := descriptorTextModes(s)
	if binary && text {
		return fmt.Errorf("%s: binary and text descriptor modes are mutually exclusive", s.Type)
	}
	return nil
}

// windowsTextReader provides the line-ending part of Cygwin O_TEXT semantics:
// external CRLF becomes LF while lone CR bytes are preserved.
type windowsTextReader struct{ r *bufio.Reader }

func newWindowsTextReader(r io.Reader) *windowsTextReader {
	return &windowsTextReader{r: bufio.NewReader(r)}
}

func (r *windowsTextReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		b, err := r.r.ReadByte()
		if err != nil {
			return written, err
		}
		if b == '\r' {
			next, err := r.r.Peek(1)
			if err == nil && next[0] == '\n' {
				_, _ = r.r.ReadByte()
				b = '\n'
			} else if err != nil && err != io.EOF {
				// ReadByte already consumed the CR. Preserve it as a lone CR
				// before surfacing a deadline, cancellation, or I/O error.
				p[written] = b
				return written + 1, err
			}
		}
		p[written] = b
		written++
	}
	return written, nil
}

// descriptorTextStream deliberately does not expose UnwrapZeroCopyStream:
// splice/TransmitFile must not bypass text translation. UnwrapStream remains
// available to deadline and descriptor-capability walks.
type descriptorTextStream struct {
	relay.Stream
	r io.Reader
	w io.Writer
}

func (s *descriptorTextStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *descriptorTextStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *descriptorTextStream) UnwrapStream() relay.Stream  { return s.Stream }

func applyDescriptorMode(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	if err := ValidateDescriptorModeOptions(s); err != nil {
		return nil, err
	}
	_, text := descriptorTextModes(s)
	if !text {
		return stream, nil
	}
	return &descriptorTextStream{
		Stream: stream,
		r:      newWindowsTextReader(stream),
		w:      &crnlWriter{w: stream},
	}, nil
}
