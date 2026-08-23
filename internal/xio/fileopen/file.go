package fileopen

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openOPEN(_ context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("OPEN requires filename")
	}
	path := s.Params[0]
	flags := OpenFlags(s, mode)
	var f *os.File
	err := xio.WithUmask(s, func() error {
		var e error
		f, e = os.OpenFile(path, flags, xio.ParseFileMode(s, 0o644)) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
		return e
	})
	if err != nil {
		// Classic format for RECVFROM_FORK_LOOP: `E open("path", …): …`
		return nil, fmt.Errorf("open(%q, %02o, %04o): %w", path, flags, xio.ParseFileMode(s, 0o666), err)
	}
	if s.HasOption("ftruncate") || s.HasOption("trunc") {
		// ftruncate=N or trunc flag after open
		if v := s.OptionValue("ftruncate", ""); v != "" {
			var n int64
			if _, e := fmt.Sscanf(v, "%d", &n); e != nil {
				_ = f.Close()
				return nil, fmt.Errorf("ftruncate: %w", e)
			}
			if e := f.Truncate(n); e != nil {
				_ = f.Close()
				return nil, fmt.Errorf("ftruncate: %w", e)
			}
		} else if s.BoolOption("trunc") {
			if e := f.Truncate(0); e != nil {
				_ = f.Close()
				return nil, fmt.Errorf("truncate: %w", e)
			}
		}
	}
	return FileOpened(f, s, path)
}

func openCREATE(_ context.Context, s parse.Spec, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("CREATE requires filename")
	}
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("CREATE is write-only")
	}
	path := s.Params[0]
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if s.BoolOption("append") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	var f *os.File
	err := xio.WithUmask(s, func() error {
		var e error
		f, e = os.OpenFile(path, flags, xio.ParseFileMode(s, 0o644)) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
		return e
	})
	if err != nil {
		return nil, err
	}
	return FileOpened(f, s, path)
}

func openGOPEN(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("GOPEN requires filename")
	}
	path := s.Params[0]
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// create regular file
			flags := os.O_RDWR | os.O_CREATE
			switch mode {
			case xio.ModeRead:
				flags = os.O_RDONLY | os.O_CREATE
			case xio.ModeWrite:
				flags = os.O_WRONLY | os.O_CREATE
			}
			var f *os.File
			err := xio.WithUmask(s, func() error {
				var e error
				f, e = os.OpenFile(path, flags, xio.ParseFileMode(s, 0o644)) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
				return e
			})
			if err != nil {
				return nil, err
			}
			return FileOpened(f, s, path)
		}
		return nil, err
	}
	// UNIX domain socket?
	if fi.Mode()&os.ModeSocket != 0 {
		return xio.OpenSpec(ctx, parse.Spec{
			// GOPEN is a generic client: classic probes stream, seqpacket,
			// and datagram sockets instead of imposing UNIX-CONNECT semantics.
			Type:    "UNIX",
			Params:  []string{path},
			Options: s.Options,
			Raw:     s.Raw,
		}, mode, g)
	}
	flags := OpenFlags(s, mode)
	// Classic GOPEN defaults to O_APPEND on existing regular files only.
	// Devices (PTY slaves via FAKEPTY link=), fifos, etc. must not get O_APPEND.
	isReg := fi.Mode().IsRegular()
	if mode != xio.ModeRead && isReg {
		if s.HasOption("append") {
			if s.BoolOption("append") {
				flags |= os.O_APPEND
			} else {
				// Explicit off: overwrite from start; truncate so shorter writes
				// do not leave trailing garbage (GOPEN_NO_APPEND).
				flags &^= os.O_APPEND
				flags |= os.O_TRUNC
			}
		} else {
			flags |= os.O_APPEND
		}
	}
	// Apply cfmakeraw etc. after open for PTY/tty devices.
	f, err := os.OpenFile(path, flags, xio.ParseFileMode(s, 0o644)) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
	if err != nil {
		return nil, err
	}
	return FileOpened(f, s, path)
}

func openPIPE(_ context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Named pipe if param present; else anonymous pipe echo
	if len(s.Params) >= 1 && s.Params[0] != "" {
		return openNamedPIPE(s, mode)
	}

	// Anonymous pipe echo: writes to the write end are readable on the read end.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	if err := xio.ApplyFDOptions(r, s); err != nil {
		logx.CloseQuiet(r)
		logx.CloseQuiet(w)
		return nil, err
	}
	return &xio.Opened{
		Stream: relay.FDStream{
			R: r,
			W: w,
			C: xio.NewMultiCloser(relay.RWCStream{ReadWriteCloser: r}, relay.RWCStream{ReadWriteCloser: w}),
			CloseW: func() error {
				return w.Close()
			},
		},
		Label: "PIPE",
		Cleanup: []func(){
			func() { logx.CloseQuiet(r); logx.CloseQuiet(w) },
		},
	}, nil
}

// openNamedPIPE creates/opens a FIFO. For bidirectional use we open separate
// read and write FDs so xio.ShutdownWrite can close the writer and deliver EOF.
func openNamedPIPE(s parse.Spec, mode xio.Mode) (*xio.Opened, error) {
	path := s.Params[0]
	created := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := xio.WithUmask(s, func() error {
			return mkfifo(path, uint32(xio.ParseFileMode(s, 0o644)))
		})
		if err != nil {
			return nil, fmt.Errorf("mkfifo %s: %w", path, err)
		}
		created = true
	}
	// Existing FIFOs receive the same explicit ownership/mode treatment. A
	// failed open must not leave behind a FIFO that this invocation created.
	if err := xio.ApplyPerm(path, s, nil); err != nil {
		if created {
			_ = os.Remove(path)
		}
		return nil, err
	}
	if err := xio.ApplyOwner(path, s, nil); err != nil {
		if created {
			_ = os.Remove(path)
		}
		return nil, err
	}

	// Classic default unlink-close=1 for named pipes (PIPE_REMOVE).
	doUnlink := created || !s.HasOption("unlink-close") || s.BoolOption("unlink-close")
	cleanupPath := func() {
		if s.BoolOption("unlink-early") {
			return
		}
		if doUnlink {
			_ = os.Remove(path)
		}
	}
	addPathCleanup := func(o *xio.Opened) {
		if s.BoolOption("unlink-early") || !doUnlink {
			return
		}
		unregister := xio.RegisterUnlinkPath(path)
		o.AddCleanup(func() {
			unregister()
			cleanupPath()
		})
	}

	clearNB := clearNonblock

	switch mode {
	case xio.ModeRead:
		// Explicit nonblock lets the read side of a dual PIPE open before its
		// write side. Otherwise, wait for a writer so the first Read cannot see
		// a premature EOF before the peer opens the FIFO.
		flags := os.O_RDONLY
		if s.BoolOption("nonblock") {
			flags |= oNonblock
		}
		f, err := os.OpenFile(path, flags, 0) // #nosec G304 -- PIPE must open the path the user gave
		if err != nil {
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		if err := xio.ApplyFDOptions(f, s); err != nil {
			logx.CloseQuiet(f)
			return nil, err
		}
		if s.BoolOption("unlink-early") {
			_ = os.Remove(path)
		}
		st, err := xio.WrapCommon(s, xio.FileStream(f))
		if err != nil {
			logx.CloseQuiet(f)
			return nil, err
		}
		o := &xio.Opened{Stream: st, Label: "PIPE:" + path}
		addPathCleanup(o)
		return o, nil
	case xio.ModeWrite:
		// Need a reader end open first for O_WRONLY on FIFO.
		r, err := os.OpenFile(path, os.O_RDONLY|oNonblock, 0) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
		if err != nil {
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		w, err := os.OpenFile(path, os.O_WRONLY|oNonblock, 0) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
		if err != nil {
			logx.CloseQuiet(r)
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		clearNB(w)
		logx.CloseQuiet(r)
		if err := xio.ApplyFDOptions(w, s); err != nil {
			logx.CloseQuiet(w)
			return nil, err
		}
		if s.BoolOption("unlink-early") {
			_ = os.Remove(path)
		}
		st, err := xio.WrapCommon(s, xio.FileStream(w))
		if err != nil {
			logx.CloseQuiet(w)
			return nil, err
		}
		o := &xio.Opened{Stream: st, Label: "PIPE:" + path}
		addPathCleanup(o)
		return o, nil
	default:
		// Bidirectional: open reader then writer (both NONBLOCK), then blocking I/O.
		r, err := os.OpenFile(path, os.O_RDONLY|oNonblock, 0) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
		if err != nil {
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		w, err := os.OpenFile(path, os.O_WRONLY|oNonblock, 0) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
		if err != nil {
			logx.CloseQuiet(r)
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		clearNB(r)
		clearNB(w)
		if err := xio.ApplyFDOptions(r, s); err != nil {
			logx.CloseQuiet(r)
			logx.CloseQuiet(w)
			return nil, err
		}
		if err := xio.ApplyFDOptions(w, s); err != nil {
			logx.CloseQuiet(r)
			logx.CloseQuiet(w)
			return nil, err
		}
		if s.BoolOption("unlink-early") {
			_ = os.Remove(path)
		}
		stream := relay.FDStream{
			R: r,
			W: w,
			C: xio.NewMultiCloser(relay.RWCStream{ReadWriteCloser: r}, relay.RWCStream{ReadWriteCloser: w}),
			CloseW: func() error {
				return w.Close()
			},
		}
		st, err := xio.WrapCommon(s, stream)
		if err != nil {
			logx.CloseQuiet(r)
			logx.CloseQuiet(w)
			return nil, err
		}
		o := &xio.Opened{Stream: st, Label: "PIPE:" + path}
		o.AddCleanup(func() { logx.CloseQuiet(r); logx.CloseQuiet(w) })
		addPathCleanup(o)
		return o, nil
	}
}

func openSocketpair(_ context.Context, s parse.Spec, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	typ, _, err := xio.SocketTypeOption(s, syscall.SOCK_STREAM)
	if err != nil {
		return nil, err
	}
	c1, c2, err := socketpairFiles(typ)
	if err != nil {
		return nil, err
	}
	for _, conn := range []*os.File{c1, c2} {
		if err := xio.ApplySocketOptions(int(conn.Fd()), s); err != nil {
			logx.CloseQuiet(c1)
			logx.CloseQuiet(c2)
			return nil, fmt.Errorf("socket options: %w", err)
		}
	}
	// Use one end only as the stream; the other end is paired so writes loop back...
	// Actually for echo we need to use BOTH ends incorrectly as one FD.
	// Classic SOCKETPAIR creates a pair and uses one "side" that is both ends merged via
	// the fact that data written to one end is read from the other — but socat uses BOTH
	// fds of the pair as a single bi-directional channel by... reading from one writing to other?
	// From man: "uses it for reading and writing. It works as an echo".
	// So they poll both and cross-connect? Looking at classic behavior: they open socketpair
	// and the address is one endpoint — writing to the address and reading from it echoes
	// because... hmm.
	//
	// Actual classic: xiosocketpair creates pair, keeps both FDs in the xio structure
	// as sockin/sockout or uses one FD with SOCK_DGRAM which might be different.
	//
	// For PIPE echo service used in tests:
	//   socat TCP4-LISTEN:port,reuseaddr PIPE
	// Data received on TCP is written to PIPE and read back from PIPE (echo).
	// The anonymous pipe in classic is opened with both ends: they use pipefd[0] for read
	// and pipefd[1] for write, so write goes to the pipe and read gets it — that's echo!
	//
	// So FDStream with R=pipe[0], W=pipe[1] is correct for anonymous PIPE.

	// Echo: write to c2 is readable on c1.
	stream, err := socketpairEchoStream(c1, c2, typ)
	if err != nil {
		logx.CloseQuiet(c1)
		logx.CloseQuiet(c2)
		return nil, err
	}
	st, err := xio.WrapCommon(s, stream)
	if err != nil {
		logx.CloseQuiet(stream)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: "SOCKETPAIR"}, nil
}

func socketpairEchoStream(c1, c2 *os.File, typ int) (relay.Stream, error) {
	closeW := func(writeEnd interface{ Close() error }, fd int) func() error {
		return func() error {
			_ = xio.ShutdownWrite(fd)
			return writeEnd.Close()
		}
	}
	if typ == syscall.SOCK_STREAM {
		return relay.FDStream{
			R:      c1,
			W:      c2,
			C:      xio.NewMultiCloser(relay.RWCStream{ReadWriteCloser: c1}, relay.RWCStream{ReadWriteCloser: c2}),
			CloseW: closeW(c2, int(c2.Fd())),
		}, nil
	}
	// Message-oriented pairs must not go through *os.File poll: empty
	// SOCK_DGRAM socketpairs can report POLLHUP, which the relay treats as
	// EOF and drops the echo. net.UnixConn uses blocking recv/send, one
	// datagram per Read/Write.
	n1, err := net.FileConn(c1)
	if err != nil {
		return nil, err
	}
	n2, err := net.FileConn(c2)
	if err != nil {
		logx.CloseQuiet(n1)
		return nil, err
	}
	logx.CloseQuiet(c1)
	logx.CloseQuiet(c2)
	s1 := relay.NetStream{Conn: n1}
	s2 := relay.NetStream{Conn: n2}
	return relay.FDStream{
		R:      s1,
		W:      s2,
		C:      xio.NewMultiCloser(s1, s2),
		CloseW: func() error { return s2.Close() },
	}, nil
}

func OpenFlags(s parse.Spec, mode xio.Mode) int {
	var flags int
	switch mode {
	case xio.ModeRead:
		flags = os.O_RDONLY
	case xio.ModeWrite:
		flags = os.O_WRONLY
	default:
		flags = os.O_RDWR
	}
	if s.BoolOption("rdonly") {
		flags = os.O_RDONLY
	}
	if s.BoolOption("wronly") {
		flags = os.O_WRONLY
	}
	if s.BoolOption("creat") || s.BoolOption("create") {
		flags |= os.O_CREATE
	}
	if s.BoolOption("excl") {
		flags |= os.O_EXCL
	}
	if s.BoolOption("append") {
		flags |= os.O_APPEND
	}
	if s.BoolOption("trunc") {
		flags |= os.O_TRUNC
	}
	if s.BoolOption("nonblock") {
		flags |= oNonblock
	}
	return flags
}

func FileOpened(f *os.File, s parse.Spec, path string) (*xio.Opened, error) {
	if err := xio.ApplyFDOptions(f, s); err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	// Classic perm=/mode= via fchmod after open (CREATE_PERM etc.).
	if err := xio.ApplyPerm(path, s, f); err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	// Classic user=/group= via fchown (CREATE_USER, OPEN_USER, GOPEN_USER).
	if err := xio.ApplyOwner(path, s, f); err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	if err := applyFileLocks(s, f, f); err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	// ignoreeof is applied centrally by xio.WrapCommon now.
	st, err := xio.WrapCommon(s, xio.FileStream(f))
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	o := &xio.Opened{
		Stream: st,
		Label:  path,
	}
	if err := xio.AttachTermios(o, int(f.Fd()), s); err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	if s.BoolOption("unlink-early") {
		_ = os.Remove(path)
	}
	if s.BoolOption("unlink-late") || s.BoolOption("unlink-close") {
		unregister := xio.RegisterUnlinkPath(path)
		o.AddCleanup(func() {
			unregister()
			_ = os.Remove(path)
		})
	}
	return o, nil
}
