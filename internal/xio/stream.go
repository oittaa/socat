package xio

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// FileStream wraps *os.File with proper half-close via shutdown(2) when possible.
// Regular files: ShutdownWrite is a no-op (closing would break shared FILE,o-append
// under fork,max-children). Pipes/FIFOs: Close to deliver EOF to the peer.
func FileStream(f *os.File) relay.Stream {
	return relay.FDStream{
		R: f,
		W: f,
		C: f,
		CloseW: func() error {
			err := shutdownWriteFile(f)
			if err == nil {
				return nil
			}
			// ENOTSOCK: do not close regular files (shared multi-child append).
			if st, e := f.Stat(); e == nil && st.Mode().IsRegular() {
				return nil
			}
			// Pipes/FIFOs: close the FD so the peer sees EOF.
			return f.Close()
		},
	}
}

// shutdownWriteFile calls shutdown(SHUT_WR) without File.Fd().
// Fd() detaches Windows IOCP and disables SetDeadline.
func shutdownWriteFile(f *os.File) error {
	sc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var shutErr error
	if err := sc.Control(func(fd uintptr) {
		shutErr = ShutdownWrite(int(fd))
	}); err != nil {
		return err
	}
	return shutErr
}

// DgramPairStream is an AF_UNIX SOCK_DGRAM socketpair end. A zero-length packet
// marks the write-side shutdown without closing the read side; full Close at
// transfer cancellation eventually releases the FD and stops the child.
func DgramPairStream(f *os.File) relay.Stream {
	var once sync.Once
	closeF := func() { once.Do(func() { _ = f.Close() }) }
	return relay.FDStream{
		R: f,
		W: f,
		C: closerFunc(func() error { closeF(); return nil }),
		CloseW: func() error {
			_, err := f.Write(nil)
			return err
		},
	}
}

type closerFunc func() error

func (c closerFunc) Close() error { return c() }

// PtyStream wraps a PTY master. ShutdownWrite does NOT close the master FD
// (unlike FileStream on non-sockets), so the reverse direction can still read
// child output until full Close. Closing the master early SIGIO/SIGHUPs the child.
func PtyStream(f *os.File) relay.Stream {
	w := &halfCloseWriter{w: f}
	return relay.FDStream{
		R: f,
		W: w,
		C: f,
		CloseW: func() error {
			w.closeWrite()
			return nil
		},
	}
}

// PtyExecStream is a PTY master for EXEC/SYSTEM. Close does not drop the
// master; finishExec waits for the child first, then closes (avoids SIGHUP
// before a SYSTEM script finishes, classic RESTORE_TTY).
func PtyExecStream(f *os.File) relay.Stream {
	w := &halfCloseWriter{w: f}
	return relay.FDStream{
		R: f,
		W: w,
		C: NopCloser{},
		CloseW: func() error {
			w.closeWrite()
			return nil
		},
	}
}

// halfCloseWriter rejects Writes after closeWrite without closing the underlying file.
type halfCloseWriter struct {
	w    io.Writer
	mu   sync.Mutex
	done bool
}

func (h *halfCloseWriter) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done {
		return 0, io.ErrClosedPipe
	}
	return h.w.Write(p)
}

func (h *halfCloseWriter) closeWrite() {
	h.mu.Lock()
	h.done = true
	h.mu.Unlock()
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

// ApplyReadBytes wraps a stream if the address has readbytes=N.
func ApplyReadBytes(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
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

// crnlWriter converts LF → CRLF on write (classic crlf/crnl: internal RAW → external CRNL).
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

// crnlReader converts external CRNL → internal RAW (classic cv_newline CRNL→RAW):
// strip every CR; leave LF and other bytes unchanged.
type crnlReader struct {
	r io.Reader
}

func (c crnlReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Keep reading until we produce at least one non-CR byte or hit error/EOF.
	// A pure-CR chunk would otherwise return (0, nil) and confuse some loops.
	tmp := make([]byte, len(p))
	out := 0
	var err error
	for out == 0 {
		var n int
		n, err = c.r.Read(tmp)
		for i := 0; i < n; i++ {
			if tmp[i] == '\r' {
				continue
			}
			p[out] = tmp[i]
			out++
		}
		if err != nil || n == 0 {
			break
		}
	}
	return out, err
}

// wantCRNL reports classic crlf/crnl line-ending conversion on an address.
// "crlf" is an alias for "crnl" in classic xioopts.c.
func wantCRNL(s parse.Spec) bool {
	return s.BoolOption("crlf") || s.BoolOption("crnl") || s.BoolOption("crorlf")
}

func ApplyCRNL(s parse.Spec, stream relay.Stream) relay.Stream {
	if !wantCRNL(s) {
		return stream
	}
	return relay.FDStream{
		R: crnlReader{r: stream},
		W: crnlWriter{w: stream},
		C: stream,
		CloseW: func() error {
			return stream.ShutdownWrite()
		},
	}
}

// escapeReader stops with EOF when the escape byte is seen (classic escape=N).
type escapeReader struct {
	r   io.Reader
	esc byte
	// leftover after escape in same Read is discarded (EOF after partial)
}

func (e *escapeReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if n > 0 {
		for i := 0; i < n; i++ {
			if p[i] == e.esc {
				// Return data before escape; next Read will EOF.
				e.r = EOFReader{}
				if i == 0 {
					return 0, io.EOF
				}
				return i, io.EOF
			}
		}
	}
	return n, err
}

func ApplyEscape(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	v := s.OptionValue("escape", "")
	if v == "" {
		return stream, nil
	}
	esc, err := parseEscapeByte(v)
	if err != nil {
		return nil, err
	}
	return relay.FDStream{
		R: &escapeReader{r: stream, esc: esc},
		W: stream,
		C: stream,
		CloseW: func() error {
			return stream.ShutdownWrite()
		},
	}, nil
}

// parseEscapeByte accepts classic escape values: decimal (27), hex with a 0x
// prefix (0x1b), or a single character. strconv.ParseUint base 0 is required
// for the hex form; fmt.Sscanf %x stops at the 'x' and would silently yield 0.
func parseEscapeByte(v string) (byte, error) {
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		n, err := strconv.ParseUint(v, 0, 8)
		if err != nil {
			return 0, fmt.Errorf("escape: invalid value %q", v)
		}
		return byte(n), nil
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 || n > 255 {
			return 0, fmt.Errorf("escape: invalid value %q", v)
		}
		return byte(n), nil
	}
	if len(v) == 1 {
		return v[0], nil
	}
	return 0, fmt.Errorf("escape: invalid value %q", v)
}

// nullEOFReader treats a zero-length successful Read as EOF (classic null-eof).
// Used with datagram sockets where a 0-byte packet signals end-of-stream.
type nullEOFReader struct {
	r io.Reader
}

func (n *nullEOFReader) Read(p []byte) (int, error) {
	nr, err := n.r.Read(p)
	if err == nil && nr == 0 {
		return 0, io.EOF
	}
	return nr, err
}

// shutNullWriter sends a 0-byte Write on ShutdownWrite (classic shut-null).
type shutNullStream struct {
	relay.Stream
}

func (s shutNullStream) UnwrapStream() relay.Stream { return s.Stream }
func (s shutNullStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

func (s shutNullStream) ShutdownWrite() error {
	_, _ = s.Write(nil) // 0-byte datagram
	return s.Stream.ShutdownWrite()
}

// socketTimeoutStream gives rcvtimeo/sndtimeo their blocking-I/O semantics on
// Go netpoll connections. Kernel SO_*TIMEO values alone do not bound reads or
// writes made through net.Conn on either Unix or Windows.
type socketTimeoutStream struct {
	relay.Stream
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (s socketTimeoutStream) UnwrapStream() relay.Stream { return s.Stream }

func (s socketTimeoutStream) Read(p []byte) (int, error) {
	if s.readTimeout > 0 {
		if _, err := relay.SetStreamReadDeadline(s.Stream, time.Now().Add(s.readTimeout)); err != nil {
			return 0, fmt.Errorf("rcvtimeo: %w", err)
		}
	}
	n, err := s.Stream.Read(p)
	if s.readTimeout > 0 && IsTimeoutErr(err) {
		return n, socketTimeoutRetryError{err: err}
	}
	return n, err
}

func (s socketTimeoutStream) Write(p []byte) (int, error) {
	if s.writeTimeout > 0 {
		if _, err := relay.SetStreamWriteDeadline(s.Stream, time.Now().Add(s.writeTimeout)); err != nil {
			return 0, fmt.Errorf("sndtimeo: %w", err)
		}
	}
	n, err := s.Stream.Write(p)
	if s.writeTimeout > 0 && IsTimeoutErr(err) {
		return n, socketTimeoutRetryError{err: err}
	}
	return n, err
}

type socketTimeoutRetryError struct{ err error }

func (e socketTimeoutRetryError) Error() string   { return e.err.Error() }
func (e socketTimeoutRetryError) Unwrap() error   { return e.err }
func (e socketTimeoutRetryError) Retryable() bool { return true }

func applySocketTimeouts(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	var readTimeout, writeTimeout time.Duration
	for _, item := range []struct {
		name string
		dst  *time.Duration
	}{
		{name: "rcvtimeo", dst: &readTimeout},
		{name: "sndtimeo", dst: &writeTimeout},
	} {
		value := s.OptionValue(item.name, "")
		if value == "" {
			continue
		}
		d, err := parseTimeval(value)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("%s: invalid timeout %q", item.name, value)
		}
		*item.dst = d
	}
	if readTimeout == 0 && writeTimeout == 0 {
		return stream, nil
	}
	return socketTimeoutStream{Stream: stream, readTimeout: readTimeout, writeTimeout: writeTimeout}, nil
}

// WrapCommon applies socket timeouts plus the common stream transformations.
func WrapCommon(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	return wrapCommon(s, stream, true)
}

// WrapCommonWithSocketTimeoutsApplied is used by framed transports that must
// absorb socket timeouts below their record layer before applying the remaining
// common stream transformations.
func WrapCommonWithSocketTimeoutsApplied(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	return wrapCommon(s, stream, false)
}

func wrapCommon(s parse.Spec, stream relay.Stream, applyTimeouts bool) (relay.Stream, error) {
	var err error
	if applyTimeouts {
		stream, err = applySocketTimeouts(s, stream)
		if err != nil {
			return nil, err
		}
	}
	// ignoreeof first so it wraps the raw source: EOF is retried (classic
	// semantics) while outer byte caps like readbytes still terminate.
	if s.BoolOption("ignoreeof") {
		stream = newIgnoreEOFStream(stream)
	}
	stream, err = ApplyReadBytes(s, stream)
	if err != nil {
		return nil, err
	}
	stream = ApplyCRNL(s, stream)
	stream, err = ApplyEscape(s, stream)
	if err != nil {
		return nil, err
	}
	if s.BoolOption("null-eof") {
		// Capture inner before reassignment — closure must not recurse on FDStream.
		inner := stream
		stream = relay.FDStream{
			R:      &nullEOFReader{r: inner},
			W:      inner,
			C:      inner,
			CloseW: func() error { return inner.ShutdownWrite() },
		}
	}
	if s.BoolOption("shut-null") || s.OptionValue("shut", "") == "null" {
		stream = shutNullStream{Stream: stream}
	}
	if s.BoolOption("shut-close") || s.OptionValue("shut", "") == "close" {
		stream = newShutCloseStream(stream)
	}
	// end-close: do not half-close or fully close the underlying FD when the
	// transfer finishes (classic TCP4ENDCLOSE / EXECENDCLOSE).
	if s.BoolOption("end-close") {
		stream = endCloseStream{Stream: stream}
	}
	return stream, nil
}

// shutCloseStream turns a directional half-close into a full descriptor
// close. This is required for SO_LINGER=0 to generate the immediate reset
// requested by classic shut-close.
type shutCloseStream struct {
	relay.Stream
	once sync.Once
	err  error
}

func newShutCloseStream(stream relay.Stream) relay.Stream {
	return &shutCloseStream{Stream: stream}
}

func (s *shutCloseStream) close() error {
	s.once.Do(func() { s.err = s.Stream.Close() })
	return s.err
}

func (s *shutCloseStream) ShutdownWrite() error       { return s.close() }
func (s *shutCloseStream) Close() error               { return s.close() }
func (s *shutCloseStream) UnwrapStream() relay.Stream { return s.Stream }
func (s *shutCloseStream) UnwrapZeroCopyStream() relay.Stream {
	return s.Stream
}

// endCloseStream suppresses ShutdownWrite and Close so the peer FD stays open.
type endCloseStream struct {
	relay.Stream
}

func (e endCloseStream) ShutdownWrite() error       { return nil }
func (e endCloseStream) Close() error               { return nil }
func (e endCloseStream) IsEndClose() bool           { return true }
func (e endCloseStream) UnwrapStream() relay.Stream { return e.Stream }
func (e endCloseStream) UnwrapZeroCopyStream() relay.Stream {
	return e.Stream
}

// streamIsEndClose reports whether s (or a wrapper) is classic end-close.
func StreamIsEndClose(s relay.Stream) bool {
	type endCloser interface{ IsEndClose() bool }
	if e, ok := s.(endCloser); ok && e.IsEndClose() {
		return true
	}
	return false
}

// ignoreEOFReader retries Read after EOF with a short, bounded backoff
// (classic ignoreeof). Cancellation closes the underlying stream, making the
// next Read return a non-EOF error; ignoreeof itself has no artificial cutoff.
type ignoreEOFReader struct {
	r        io.Reader
	minDelay time.Duration
	maxDelay time.Duration
	delay    time.Duration
	done     chan struct{}
	close    sync.Once
}

func NewIgnoreEOF(r io.Reader) *ignoreEOFReader {
	return &ignoreEOFReader{
		r:        r,
		minDelay: time.Millisecond,
		maxDelay: time.Second,
		delay:    time.Millisecond,
		done:     make(chan struct{}),
	}
}

func (i *ignoreEOFReader) Read(p []byte) (int, error) {
	for {
		n, err := i.r.Read(p)
		if n > 0 {
			i.delay = i.minDelay
			return n, nil
		}
		if err == nil {
			continue
		}
		if err != io.EOF {
			return 0, err
		}
		// EOF: retry quickly at first so a concurrent append is observed before
		// short relay linger timers expire, then back off during long idle periods.
		timer := time.NewTimer(i.delay)
		select {
		case <-timer.C:
		case <-i.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return 0, net.ErrClosed
		}
		if i.delay < i.maxDelay {
			i.delay = min(i.delay*2, i.maxDelay)
		}
	}
}

func (i *ignoreEOFReader) Close() error {
	i.close.Do(func() { close(i.done) })
	return nil
}

type ignoreEOFStream struct {
	relay.Stream
	reader *ignoreEOFReader
}

func newIgnoreEOFStream(inner relay.Stream) relay.Stream {
	return &ignoreEOFStream{Stream: inner, reader: NewIgnoreEOF(inner)}
}

func (s *ignoreEOFStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *ignoreEOFStream) Close() error {
	return errors.Join(s.reader.Close(), s.Stream.Close())
}
func (s *ignoreEOFStream) UnwrapStream() relay.Stream { return s.Stream }

// NopCloser is a no-op Closer.
type NopCloser struct{}

func (NopCloser) Close() error { return nil }
