package xio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
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

func ptyExecStream(f *os.File, r io.Reader) relay.Stream {
	w := &halfCloseWriter{w: f}
	return relay.FDStream{
		R: r,
		W: w,
		C: NopCloser{},
		CloseW: func() error {
			w.closeWrite()
			return nil
		},
	}
}

// PtyStreamConfigured wraps a PTY master using prepared terminal settings.
func PtyStreamConfigured(f *os.File, config addrconfig.Terminal) (relay.Stream, error) {
	r, err := configuredPTYMasterReader(f, config)
	if err != nil {
		return nil, err
	}
	w := &halfCloseWriter{w: f}
	return relay.FDStream{
		R: r,
		W: w,
		C: f,
		CloseW: func() error {
			w.closeWrite()
			return nil
		},
	}, nil
}

func configuredPTYMasterReader(f *os.File, config addrconfig.Terminal) (io.Reader, error) {
	var delay time.Duration
	if config.SitoutEIO.Set {
		delay = config.SitoutEIO.Value
	}
	return wrapSitoutEIORead(f, delay), nil
}

// halfCloseWriter rejects Writes after closeWrite without closing the underlying file.
type halfCloseWriter struct {
	w    io.Writer
	mu   sync.Mutex
	done bool
}

func (h *halfCloseWriter) UnwrapWriter() io.Writer { return h.w }

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

// SyscallConn exposes the underlying *os.File so one-way EXEC/PTY streams
// (writer-only halfCloseWriter) still receive after-open and late options.
func (h *halfCloseWriter) SyscallConn() (syscall.RawConn, error) {
	sc, ok := h.w.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("half-close writer does not expose a descriptor")
	}
	return sc.SyscallConn()
}

// streamWithReader changes only reading, retaining ownership and shutdown.
// FDStream keeps the read and write capability paths separate.
func streamWithReader(stream relay.Stream, r io.Reader) relay.Stream {
	return relay.FDStream{R: r, W: stream, C: stream, CloseW: stream.ShutdownWrite}
}

// readBytesWrap limits total bytes read (readbytes=N).
type readBytesWrap struct {
	r    io.Reader
	left uint64
}

func (r *readBytesWrap) UnwrapReader() io.Reader { return r.r }

func (r *readBytesWrap) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	if uint64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.r.Read(p)
	if n > 0 {
		r.left -= uint64(n)
	}
	if r.left == 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// ApplyReadBytes wraps a stream if the address has readbytes=N.
// Size is parsed with base 0 (decimal, 0x hex, 0 octal).
// readbytes=0 means unlimited and leaves the stream unwrapped.
func ApplyReadBytes(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return nil, err
	}
	return applyReadBytes(config.Transfer.ReadBytes, stream), nil
}

func applyReadBytes(limit addrconfig.OptionalUint64, stream relay.Stream) relay.Stream {
	if !limit.Set || limit.Value == 0 {
		return stream
	}
	return streamWithReader(stream, &readBytesWrap{r: stream, left: limit.Value})
}

// crnlWriter converts LF → CRLF on write (internal RAW → external CRNL).
type crnlWriter struct {
	w         io.Writer
	pendingLF bool
	lf        [1]byte
	crlf      [2]byte
}

func (c *crnlWriter) Write(p []byte) (int, error) {
	// Expand \n to \r\n; report original len for io.Copy compatibility-ish.
	// If \r of a CRLF is written and \n is not, remember that so a retry of
	// the same input byte cannot emit a second \r (sndtimeo short writes).
	written := 0
	c.lf[0] = '\n'
	c.crlf[0], c.crlf[1] = '\r', '\n'
	if c.pendingLF {
		n, err := c.w.Write(c.lf[:])
		if n == 1 {
			c.pendingLF = false
			if len(p) > 0 && p[0] == '\n' {
				written++
				p = p[1:]
			}
			if err != nil {
				return written, err
			}
		} else {
			if err == nil {
				err = io.ErrShortWrite
			}
			return 0, err
		}
	}
	for len(p) > 0 {
		i := 0
		for i < len(p) && p[i] != '\n' {
			i++
		}
		if i > 0 {
			n, err := c.w.Write(p[:i])
			written += n
			if n != i && err == nil {
				err = io.ErrShortWrite
			}
			if err != nil {
				return written, err
			}
			p = p[i:]
		}
		if len(p) > 0 && p[0] == '\n' {
			n, err := c.w.Write(c.crlf[:])
			switch n {
			case 0:
				if err == nil {
					err = io.ErrShortWrite
				}
				return written, err
			case 1:
				c.pendingLF = true
				if err != nil {
					return written, err
				}
				n, err = c.w.Write(c.lf[:])
				if n != 1 {
					if err == nil {
						err = io.ErrShortWrite
					}
					return written, err
				}
				c.pendingLF = false
			case 2:
			default:
				return written, io.ErrShortWrite
			}
			written++
			p = p[1:]
			if err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// crnlReader converts external CRNL → internal RAW: strip every CR; leave
// LF and other bytes unchanged.
type crnlReader struct {
	r   io.Reader
	tmp []byte
}

func (c *crnlReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Keep reading until at least one non-CR byte is produced or error/EOF.
	// A pure-CR chunk would otherwise return (0, nil) and confuse some loops.
	c.tmp = resizeScratch(c.tmp, len(p))
	out := 0
	var err error
	for out == 0 {
		var n int
		n, err = c.r.Read(c.tmp)
		for i := 0; i < n; i++ {
			if c.tmp[i] == '\r' {
				continue
			}
			p[out] = c.tmp[i]
			out++
		}
		if err != nil || n == 0 {
			break
		}
	}
	return out, err
}

// crWriter converts NL → CR on write (RAW → CR).
type crWriter struct {
	w   io.Writer
	buf []byte
}

func (c *crWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.buf = resizeScratch(c.buf, len(p))
	copy(c.buf, p)
	for i, b := range c.buf {
		if b == '\n' {
			c.buf[i] = '\r'
		}
	}
	return c.w.Write(c.buf)
}

// crReader converts CR → NL on read (CR → RAW).
type crReader struct{ r io.Reader }

func (c crReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	for i := 0; i < n; i++ {
		if p[i] == '\r' {
			p[i] = '\n'
		}
	}
	return n, err
}

// crorlfReader converts CR, LF, or CRLF → NL. Distinct from crnl (which
// strips CR) and cr (which is a 1:1 CR↔NL swap).
type crorlfReader struct {
	r     io.Reader
	sawCR bool
	tmp   []byte
}

func (c *crorlfReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.tmp = resizeScratch(c.tmp, len(p))
	out := 0
	var err error
	for out == 0 {
		var n int
		n, err = c.r.Read(c.tmp)
		for i := 0; i < n && out < len(p); i++ {
			b := c.tmp[i]
			if c.sawCR && b == '\n' {
				c.sawCR = false
				continue
			}
			c.sawCR = b == '\r'
			if b == '\r' || b == '\n' {
				p[out] = '\n'
			} else {
				p[out] = b
			}
			out++
		}
		if err != nil || n == 0 {
			break
		}
	}
	return out, err
}

func resizeScratch(buf []byte, size int) []byte {
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

// transformStream delegates converted I/O. Zero-copy is cleared so splice
// cannot skip conversion.
type transformStream struct {
	relay.Stream
	r io.Reader
	w io.Writer
}

func (s *transformStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *transformStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *transformStream) UnwrapStream() relay.Stream  { return s.Stream }
func (s *transformStream) StreamProps() relay.Props {
	return relay.WithoutZeroCopy(relay.PropsOf(s.Stream))
}

func applyLineTerm(ending addrconfig.LineEnding, stream relay.Stream) relay.Stream {
	switch ending {
	case addrconfig.LineEndingCR:
		return &transformStream{Stream: stream, r: crReader{r: stream}, w: &crWriter{w: stream}}
	case addrconfig.LineEndingCRNL:
		return &transformStream{Stream: stream, r: &crnlReader{r: stream}, w: &crnlWriter{w: stream}}
	case addrconfig.LineEndingCROrLF:
		return &transformStream{Stream: stream, r: &crorlfReader{r: stream}, w: &crnlWriter{w: stream}}
	default:
		return stream
	}
}

// ApplyCRNL wraps a stream with the selected line-termination mode.
func ApplyCRNL(s parse.Spec, stream relay.Stream) (relay.Stream, error) {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return nil, err
	}
	return applyLineTerm(config.Transfer.LineEnding, stream), nil
}

// escapeReader stops with EOF when the escape byte is seen (escape=N).
type escapeReader struct {
	r   io.Reader
	esc byte
	// leftover after escape in same Read is discarded (EOF after partial)
}

func (r *escapeReader) UnwrapReader() io.Reader { return r.r }

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
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return nil, err
	}
	return applyEscape(config.Transfer.Escape, stream), nil
}

func applyEscape(esc addrconfig.OptionalByte, stream relay.Stream) relay.Stream {
	if !esc.Set {
		return stream
	}
	return streamWithReader(stream, &escapeReader{r: stream, esc: esc.Value})
}

// nullEOFReader treats a zero-length successful Read as EOF (null-eof).
// Used with datagram sockets where a 0-byte packet signals end-of-stream.
// A zero-length destination is not a read and is left unchanged.
type nullEOFReader struct {
	r io.Reader
}

func (r *nullEOFReader) UnwrapReader() io.Reader { return r.r }

func (n *nullEOFReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	nr, err := n.r.Read(p)
	if err == nil && nr == 0 {
		return 0, io.EOF
	}
	return nr, err
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
func (s socketTimeoutStream) StreamProps() relay.Props {
	return relay.WithoutZeroCopy(relay.PropsOf(s.Stream))
}

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

func applySocketTimeouts(config addrconfig.Address, stream relay.Stream) relay.Stream {
	readTimeout := config.Common.Timeouts.Read.Value
	writeTimeout := config.Common.Timeouts.Write.Value
	if readTimeout == 0 && writeTimeout == 0 {
		return stream
	}
	return socketTimeoutStream{Stream: stream, readTimeout: readTimeout, writeTimeout: writeTimeout}
}

// SocketTimeoutLayer selects where read/write timeouts are enforced.
type SocketTimeoutLayer uint8

const (
	StreamSocketTimeouts SocketTimeoutLayer = iota
	TransportSocketTimeouts
)

// WrapStream applies stream transformations after transport setup is complete.
// TLS enforces timeouts below its record layer; other streams enforce them here.
func WrapStream(s parse.Spec, stream relay.Stream, timeouts SocketTimeoutLayer) (relay.Stream, error) {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return nil, err
	}
	// O_BINARY/O_TEXT are descriptor-level conversions. Keep the wrapper
	// inside user-requested cr/crnl, readbytes, escape, and ignoreeof layers,
	// and do not let zero-copy bypass it.
	stream, err = applyDescriptorMode(s, stream)
	if err != nil {
		return nil, err
	}
	if timeouts == StreamSocketTimeouts {
		stream = applySocketTimeouts(config, stream)
	}
	// ignoreeof first so it wraps the raw source: EOF is retried while
	// outer byte caps like readbytes still terminate.
	if config.Transfer.IgnoreEOF.Value {
		stream = newIgnoreEOFStream(stream)
	}
	stream = applyReadBytes(config.Transfer.ReadBytes, stream)
	stream = applyLineTerm(config.Transfer.LineEnding, stream)
	stream = applyEscape(config.Transfer.Escape, stream)
	if config.Transfer.NullEOF.Value {
		stream = streamWithReader(stream, &nullEOFReader{r: stream})
	}
	stream = wrapTransferShut(config.Transfer.Shutdown, stream)
	// end-close: do not half-close or fully close the underlying FD when the
	// transfer finishes.
	if config.Transfer.EndClose.Value {
		stream = endCloseStream{Stream: stream}
	}
	return stream, nil
}

// endCloseStream suppresses ShutdownWrite and Close so the peer FD stays open.
type endCloseStream struct {
	relay.Stream
}

func (e endCloseStream) ShutdownWrite() error       { return nil }
func (e endCloseStream) Close() error               { return nil }
func (e endCloseStream) IsEndClose() bool           { return true }
func (e endCloseStream) UnwrapStream() relay.Stream { return e.Stream }

// StreamIsEndClose reports whether s (or a wrapper) is end-close.
func StreamIsEndClose(s relay.Stream) bool {
	type endCloser interface{ IsEndClose() bool }
	if e, ok := s.(endCloser); ok && e.IsEndClose() {
		return true
	}
	return false
}

// ignoreEOFReader retries Read after EOF with a short, bounded backoff.
// Cancellation closes the underlying stream, making the next Read return a
// non-EOF error; ignoreeof itself has no artificial cutoff.
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
func (s *ignoreEOFStream) StreamProps() relay.Props {
	return relay.WithoutZeroCopy(relay.PropsOf(s.Stream))
}

// NopCloser is a no-op Closer.
type NopCloser struct{}

func (NopCloser) Close() error { return nil }
