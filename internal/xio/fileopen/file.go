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

// openUserFile opens the user-specified path of an address. It is the single
// audited choke point for user-controlled path opens in this package.
func openUserFile(path string, flags int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags, perm) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
}

// openUserFileWithUmask opens path under the process umask (classic umask=).
// Use this for CREATE/OPEN and GOPEN's create path. Existing-file opens and
// FIFO open(2) after mkfifo use openUserFile; mkfifo has its own WithUmask.
func openUserFileWithUmask(s parse.Spec, path string, flags int, perm os.FileMode) (*os.File, error) {
	var f *os.File
	err := xio.WithUmask(s, func() error {
		var e error
		f, e = openUserFile(path, flags, perm)
		return e
	})
	return f, err
}

func openOPEN(_ context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("OPEN requires filename")
	}
	path := s.Params[0]
	flags, err := OpenFlags(s, mode)
	if err != nil {
		return nil, err
	}
	perm, err := xio.ParseFileMode(s, xio.DefaultCreateMode)
	if err != nil {
		return nil, err
	}
	if _, err := namedOpenEarly(path, s); err != nil {
		return nil, err
	}
	f, err := openUserFileWithUmask(s, path, flags, perm)
	if err != nil {
		// Classic format for RECVFROM_FORK_LOOP: `E open("path", …): …`
		return nil, fmt.Errorf("open(%q, %02o, %04o): %w", path, flags, xio.FileModeToUnix(perm), err)
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
	// Classic CREATE is GROUP_FD|GROUP_NAMED|GROUP_FILE, not GROUP_OPEN
	// (xio-creat.c, tag-1.8.1.3). o-direct is GROUP_OPEN / PH_OPEN, so it
	// is rejected at option validation rather than applied here.
	perm, err := xio.ParseFileMode(s, xio.DefaultCreateMode)
	if err != nil {
		return nil, err
	}
	if _, err := namedOpenEarly(path, s); err != nil {
		return nil, err
	}
	f, err := openUserFileWithUmask(s, path, flags, perm)
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
	early, err := namedOpenEarly(path, s)
	if err != nil {
		return nil, err
	}
	if !early.exists {
		// create regular file
		flags := os.O_RDWR | os.O_CREATE
		switch mode {
		case xio.ModeRead:
			flags = os.O_RDONLY | os.O_CREATE
		case xio.ModeWrite:
			flags = os.O_WRONLY | os.O_CREATE
		}
		flags, ferr := applyODirectFlag(s, flags)
		if ferr != nil {
			return nil, ferr
		}
		perm, perr := xio.ParseFileMode(s, xio.DefaultCreateMode)
		if perr != nil {
			return nil, perr
		}
		f, err := openUserFileWithUmask(s, path, flags, perm)
		if err != nil {
			return nil, err
		}
		return FileOpened(f, s, path)
	}
	// UNIX domain socket? Uses the pre-unlink Stat snapshot: PH_PREOPEN
	// unlink does not reclassify a socket as a missing create-path.
	if early.mode&os.ModeSocket != 0 {
		o, err := xio.OpenSpec(ctx, parse.Spec{
			// GOPEN is a generic client: classic probes stream, seqpacket,
			// and datagram sockets instead of imposing UNIX-CONNECT semantics.
			Type:    "UNIX",
			Params:  []string{path},
			Options: s.Options,
			Raw:     s.Raw,
		}, mode, g)
		if err != nil {
			return nil, err
		}
		// Classic GOPEN of a socket applies PH_PASTOPEN unlink-late on the
		// path after connect; unlink-close is only armed for non-sockets.
		if err := applyNamedUnlinkLate(path, s); err != nil {
			logx.CloseQuiet(o)
			return nil, err
		}
		return o, nil
	}
	flags, err := OpenFlags(s, mode)
	if err != nil {
		return nil, err
	}
	// Classic GOPEN defaults to O_APPEND on existing regular files only.
	// Devices (PTY slaves via FAKEPTY link=), fifos, etc. must not get O_APPEND.
	isReg := early.mode.IsRegular()
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
	perm, err := xio.ParseFileMode(s, xio.DefaultCreateMode)
	if err != nil {
		return nil, err
	}
	f, err := openUserFile(path, flags, perm)
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
	if err := rejectUnnamedPIPEODirect(s); err != nil {
		return nil, err
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
	st, err := xio.WrapCommon(s, relay.FDStream{
		R: r,
		W: w,
		C: xio.NewMultiCloser(relay.RWCStream{ReadWriteCloser: r}, relay.RWCStream{ReadWriteCloser: w}),
		CloseW: func() error {
			return w.Close()
		},
	})
	if err != nil {
		logx.CloseQuiet(r)
		logx.CloseQuiet(w)
		return nil, err
	}
	return &xio.Opened{
		Stream: st,
		Label:  "PIPE",
		Cleanup: []func(){
			func() { logx.CloseQuiet(r); logx.CloseQuiet(w) },
		},
	}, nil
}

// openNamedPIPE creates/opens a FIFO. For bidirectional use we open separate
// read and write FDs so xio.ShutdownWrite can close the writer and deliver EOF.
func openNamedPIPE(s parse.Spec, mode xio.Mode) (*xio.Opened, error) {
	path := s.Params[0]
	// Classic xio-pipe.c (tag-1.8.1.3
	// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a): unlink-early Unlink()s
	// even when the name is missing; ENOENT aborts before mkfifo. OPEN /
	// CREATE / GOPEN instead share namedOpenEarly (exists && unlink-early).
	if s.BoolOption("unlink-early") {
		if err := xio.Unlink(path); err != nil {
			return nil, fmt.Errorf("unlink %s: %w", path, err)
		}
	}
	// PH_PREOPEN (perm-early / user-early / group-early / unlink) in
	// command-line order when the name still exists after unlink-early.
	if _, err := namedOpenEarly(path, s); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := xio.WithUmask(s, func() error {
			perm, perr := xio.ParseUnixMode(s, uint32(xio.DefaultCreateMode))
			if perr != nil {
				return perr
			}
			return mkfifo(path, perm)
		})
		if err != nil {
			return nil, fmt.Errorf("mkfifo %s: %w", path, err)
		}
		created = true
	}
	// Existing FIFOs receive the same explicit ownership treatment. A
	// failed open must not leave behind a FIFO that this invocation created.
	if err := xio.ApplyOwner(path, s, nil); err != nil {
		if created {
			_ = xio.Unlink(path)
		}
		return nil, err
	}

	// Classic xio-pipe.c (tag-1.8.1.3,
	// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a): after Mkfifo, before the
	// possibly blocking open, record unlink_close so SIGTERM removes the FIFO
	// (test.sh PIPE_REMOVE). Only the creating process unlinks, and
	// unlink-close=0 keeps the entry.
	doUnlink := created && (!s.HasOption("unlink-close") || s.BoolOption("unlink-close"))
	unregister := func() {}
	if doUnlink {
		unregister = xio.RegisterUnlinkPath(path)
	}
	removeCreated := func() {
		if created {
			unregister()
			_ = xio.Unlink(path)
		}
	}
	cleanupPath := func() {
		if doUnlink {
			_ = xio.Unlink(path)
		}
	}
	addPathCleanup := func(o *xio.Opened) {
		if !doUnlink {
			return
		}
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
		f, err := openFIFO(path, flags, s)
		if err != nil {
			removeCreated()
			return nil, err
		}
		if err := applyNamedUnlinkLate(path, s); err != nil {
			logx.CloseQuiet(f)
			removeCreated()
			return nil, err
		}
		if err := xio.ApplyFDOptions(f, s); err != nil {
			logx.CloseQuiet(f)
			removeCreated()
			return nil, err
		}
		st, err := xio.WrapCommon(s, xio.FileStream(f))
		if err != nil {
			logx.CloseQuiet(f)
			removeCreated()
			return nil, err
		}
		o := &xio.Opened{Stream: st, Label: "PIPE:" + path}
		addPathCleanup(o)
		return o, nil
	case xio.ModeWrite:
		// Need a reader end open first for O_WRONLY on FIFO. The dummy reader
		// is not a classic fd; o-direct applies only to the user-facing writer
		// (xio-pipe.c → _xioopen_open).
		r, err := openUserFile(path, os.O_RDONLY|oNonblock, 0)
		if err != nil {
			removeCreated()
			return nil, err
		}
		w, err := openFIFO(path, os.O_WRONLY|oNonblock, s)
		if err != nil {
			logx.CloseQuiet(r)
			removeCreated()
			return nil, err
		}
		clearNB(w)
		logx.CloseQuiet(r)
		if err := applyNamedUnlinkLate(path, s); err != nil {
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
		}
		if err := xio.ApplyFDOptions(w, s); err != nil {
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
		}
		st, err := xio.WrapCommon(s, xio.FileStream(w))
		if err != nil {
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
		}
		o := &xio.Opened{Stream: st, Label: "PIPE:" + path}
		addPathCleanup(o)
		return o, nil
	default:
		// Bidirectional: open reader then writer (both NONBLOCK), then blocking I/O.
		r, err := openFIFO(path, os.O_RDONLY|oNonblock, s)
		if err != nil {
			removeCreated()
			return nil, err
		}
		w, err := openFIFO(path, os.O_WRONLY|oNonblock, s)
		if err != nil {
			logx.CloseQuiet(r)
			removeCreated()
			return nil, err
		}
		clearNB(r)
		clearNB(w)
		if err := applyNamedUnlinkLate(path, s); err != nil {
			logx.CloseQuiet(r)
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
		}
		if err := xio.ApplyFDOptions(r, s); err != nil {
			logx.CloseQuiet(r)
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
		}
		if err := xio.ApplyFDOptions(w, s); err != nil {
			logx.CloseQuiet(r)
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
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
			removeCreated()
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
		if err := xio.ApplySocketOptionsWithoutGeneric(int(conn.Fd()), s); err != nil {
			logx.CloseQuiet(c1)
			logx.CloseQuiet(c2)
			return nil, fmt.Errorf("socket options: %w", err)
		}
		// Classic xiosocketpair applyopts(PH_ALL) on both fds (tag-1.8.1.3
		// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
		// af5388c898c7bb60997935aee93c223deba60c4a is the same). Thus every
		// generic phase is applied once per fd in original option order.
		if err := xio.ApplyGenericSetsockoptAll(int(conn.Fd()), s); err != nil {
			logx.CloseQuiet(c1)
			logx.CloseQuiet(c2)
			return nil, fmt.Errorf("setsockopt: %w", err)
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
	st, err := xio.WrapCommonAfterConnected(s, stream)
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

func OpenFlags(s parse.Spec, mode xio.Mode) (int, error) {
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
	// o-direct is classic PH_OPEN / OFUNC_FLAG (xio-file.c). Apply only at
	// open(2); do not F_SETFL it onto inherited descriptors (contrast
	// o-noatime, which is PH_FD).
	return applyODirectFlag(s, flags)
}

func applyODirectFlag(s parse.Spec, flags int) (int, error) {
	if !s.BoolOption("o-direct") {
		return flags, nil
	}
	if oDirect == 0 {
		return 0, fmt.Errorf("o-direct: not supported on this platform")
	}
	return flags | oDirect, nil
}

// openFIFO opens a named FIFO. Classic PIPE is GROUP_OPEN, so o-direct
// (PH_OPEN / OFUNC_FLAG in xio-file.c) is OR'd into open(2) the same way
// _xioopen_open does (xio-pipe.c, tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a).
func openFIFO(path string, flags int, s parse.Spec) (*os.File, error) {
	flags, err := applyODirectFlag(s, flags)
	if err != nil {
		return nil, err
	}
	return openUserFile(path, flags, 0)
}

// rejectUnnamedPIPEODirect matches classic leftover-option failure: unnamed
// PIPE uses pipe(2), not open(2), so PH_OPEN OFUNC_FLAG o-direct is never
// consumed. Do not F_SETFL O_DIRECT onto the pipe fds.
func rejectUnnamedPIPEODirect(s parse.Spec) error {
	if !s.BoolOption("o-direct") {
		return nil
	}
	if oDirect == 0 {
		return fmt.Errorf("o-direct: not supported on this platform")
	}
	return fmt.Errorf("o-direct: not supported on unnamed PIPE")
}

func applyOpenTruncate(f *os.File, s parse.Spec) error {
	// Named-file ftruncate stays here so OPEN/CREATE/GOPEN still truncate
	// once (ApplyFDOptions skips these types) and Windows keeps working.
	// FD:n / inherited descriptors use ftruncate(2) in ApplyFDOptions.
	// Classic applyopts PH_LATE issues every ftruncate/truncate/ftruncate32/64
	// occurrence in command-line order (tag-1.8.1.3
	// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a).
	if s.HasOption("ftruncate") {
		return xio.ApplyNamedFileFtruncate(f, s)
	}
	if s.BoolOption("trunc") {
		if e := f.Truncate(0); e != nil {
			return fmt.Errorf("truncate: %w", e)
		}
	}
	return nil
}

func FileOpened(f *os.File, s parse.Spec, path string) (*xio.Opened, error) {
	// Classic _xioopen_open applies PH_PASTOPEN unlink-late immediately after
	// open(2). unlink-close is armed before FD/owner/lock/wrap/termios so a
	// later failure still removes the name (xio-file.c / xio-gopen.c).
	guard, err := namedAfterOpen(path, s)
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	fail := func(err error) (*xio.Opened, error) {
		logx.CloseQuiet(f)
		guard.drop()
		return nil, err
	}
	if err := applyOpenTruncate(f, s); err != nil {
		return fail(err)
	}
	if err := xio.ApplyFDOptions(f, s); err != nil {
		return fail(err)
	}
	// Classic perm=/user= after open apply to named sockets and PTY slaves.
	// Regular files use perm=/mode= as the open(2) creation mode so umask
	// still masks the result (umask=077,perm=0666 → 0600).
	if err := xio.ApplyOwner(path, s, f); err != nil {
		return fail(err)
	}
	if err := applyFileLocks(s, f, f); err != nil {
		return fail(err)
	}
	// ignoreeof is applied centrally by xio.WrapCommon now.
	st, err := xio.WrapCommon(s, xio.FileStream(f))
	if err != nil {
		return fail(err)
	}
	o := &xio.Opened{
		Stream: st,
		Label:  path,
	}
	if err := xio.AttachTermios(o, int(f.Fd()), s); err != nil {
		return fail(err)
	}
	guard.attach(o)
	return o, nil
}
