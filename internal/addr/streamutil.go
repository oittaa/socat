package addr

import (
	"fmt"
	"io"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// fileStream wraps *os.File with proper half-close via shutdown(2) when possible.
// For non-sockets (FIFOs, regular files), falls back to Close so peers see EOF.
func fileStream(f *os.File) relay.Stream {
	return relay.FDStream{
		R: f,
		W: f,
		C: f,
		CloseW: func() error {
			err := unix.Shutdown(int(f.Fd()), unix.SHUT_WR)
			if err != nil {
				// ENOTSOCK and friends: close the FD to signal EOF on pipes/FIFOs.
				return f.Close()
			}
			return nil
		},
	}
}

// readBytesWrap limits total bytes read (classic readbytes=N).
type readBytesWrap struct {
	r    io.Reader
	left int64
}

func (r *readBytesWrap) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.r.Read(p)
	r.left -= int64(n)
	if r.left <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// applyReadBytes wraps a stream if the address has readbytes=N.
func applyReadBytes(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	v := s.OptionValue("readbytes", "")
	if v == "" {
		return stream, nil
	}
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 0 {
		return nil, fmt.Errorf("invalid readbytes %q", v)
	}
	return relay.FDStream{
		R: &readBytesWrap{r: stream, left: n},
		W: stream,
		C: stream,
		CloseW: func() error {
			return stream.ShutdownWrite()
		},
	}, nil
}

// crnlWriter converts LF → CRLF on write (classic crnl option, basic form).
type crnlWriter struct {
	w io.Writer
}

func (c crnlWriter) Write(p []byte) (int, error) {
	// Expand \n to \r\n; report original len for io.Copy compatibility-ish
	written := 0
	for len(p) > 0 {
		i := 0
		for i < len(p) && p[i] != '\n' {
			i++
		}
		if i > 0 {
			n, err := c.w.Write(p[:i])
			written += n
			if err != nil {
				return written, err
			}
			p = p[i:]
		}
		if len(p) > 0 && p[0] == '\n' {
			if _, err := c.w.Write([]byte{'\r', '\n'}); err != nil {
				return written, err
			}
			written++ // count as 1 input byte
			p = p[1:]
		}
	}
	return written, nil
}

func applyCRNL(s parse.Spec, stream relay.Stream) relay.Stream {
	if !s.BoolOption("crnl") && !s.BoolOption("crorlf") {
		return stream
	}
	return relay.FDStream{
		R: stream,
		W: crnlWriter{w: stream},
		C: stream,
		CloseW: func() error {
			return stream.ShutdownWrite()
		},
	}
}

// wrapCommon applies readbytes / crnl / ignoreeof-style wrappers after open.
func wrapCommon(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	var err error
	stream, err = applyReadBytes(s, stream)
	if err != nil {
		return nil, err
	}
	stream = applyCRNL(s, stream)
	return stream, nil
}
