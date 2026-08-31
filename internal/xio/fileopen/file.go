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

// openUserFileWithUmask opens path under the process umask (umask=).
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
		// Error text is open("path", …) so RECVFROM_FORK_LOOP parsers match it.
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
		// CREATE uses creat(2) semantics (always truncates first). append is
		// late; O_TRUNC|O_APPEND has the same descriptor semantics without
		// preserving stale contents.
		flags |= os.O_APPEND
	}
	// CREATE does not take open(2) flags (o-direct, o-sync, …); those are
	// rejected at option validation rather than applied here.
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
		flags, ferr := applyOpenFlags(s, flags)
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
	// UNIX domain socket? Uses the pre-unlink os.Stat snapshot: unlink
	// after the name exists, before open, does not reclassify a socket as
	// a missing create-path.
	if early.mode&os.ModeSocket != 0 {
		if err := rejectGOPENSocketOpenFlags(s); err != nil {
			return nil, err
		}
		o, err := xio.OpenSpec(ctx, parse.Spec{
			// GOPEN is a generic client: it probes stream, seqpacket, and
			// datagram sockets instead of imposing UNIX-CONNECT semantics.
			Type:    "UNIX",
			Params:  []string{path},
			Options: s.Options,
			Raw:     s.Raw,
		}, mode, g)
		if err != nil {
			return nil, err
		}
		// GOPEN of a socket applies unlink-late after connect; unlink-close
		// is only armed for non-sockets.
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
	// GOPEN defaults to O_APPEND on existing regular files only.
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
	if err := rejectUnnamedPIPEOpenFlags(s); err != nil {
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
	// unlink-early unlinks even when the name is missing; ENOENT aborts
	// before mkfifo. OPEN / CREATE / GOPEN instead share namedOpenEarly
	// (exists && unlink-early).
	if s.BoolOption("unlink-early") {
		if err := xio.Unlink(path); err != nil {
			return nil, fmt.Errorf("unlink %s: %w", path, err)
		}
	}
	// perm-early / user-early / group-early / unlink in command-line order
	// when the name still exists after unlink-early.
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
	// Ownership applies to a newly created FIFO immediately, but to an
	// existing FIFO only after open succeeds.
	if created {
		if err := xio.ApplyOwner(path, s, nil); err != nil {
			_ = xio.Unlink(path)
			return nil, err
		}
	}
	applyExistingOwner := func() error {
		if created {
			return nil
		}
		return xio.ApplyOwner(path, s, nil)
	}

	// After mkfifo, before the possibly blocking open, register unlink-close
	// so SIGTERM removes the FIFO. Only the creating process unlinks;
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
		if err := applyExistingOwner(); err != nil {
			logx.CloseQuiet(f)
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
		// is not an address fd; o-direct applies only to the user-facing writer.
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
		if err := applyExistingOwner(); err != nil {
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
		}
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
		if err := applyExistingOwner(); err != nil {
			logx.CloseQuiet(r)
			logx.CloseQuiet(w)
			removeCreated()
			return nil, err
		}
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
		// Apply every generic setsockopt phase once per fd, in original option
		// order (broadcast, sndbuf, linger, … included).
		if err := xio.ApplyGenericSetsockoptAll(int(conn.Fd()), s); err != nil {
			logx.CloseQuiet(c1)
			logx.CloseQuiet(c2)
			return nil, fmt.Errorf("setsockopt: %w", err)
		}
	}
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
	// Walk rdonly/wronly/rdwr in command-line order; each one replaces the
	// access mode. Preserve that ordering across aliases instead of making
	// wronly win unconditionally.
	for _, o := range s.Options {
		if !o.Active() {
			continue
		}
		switch parse.CanonicalOptionName(o.Name) {
		case "rdonly":
			flags = os.O_RDONLY
		case "wronly":
			flags = os.O_WRONLY
		case "rdwr":
			flags = os.O_RDWR
		}
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
	// o-direct, o-sync, … and async apply only at open(2); do not F_SETFL
	// o-direct onto inherited descriptors (contrast o-noatime, which is
	// after open, on the descriptor).
	return applyOpenFlags(s, flags)
}

// openFIFO opens a named FIFO. o-direct, o-sync, … and async are OR'd
// into open(2).
func openFIFO(path string, flags int, s parse.Spec) (*os.File, error) {
	flags, err := applyOpenFlags(s, flags)
	if err != nil {
		return nil, err
	}
	return openUserFile(path, flags, 0)
}

func applyOpenTruncate(f *os.File, s parse.Spec) error {
	// ftruncate is late and is applied by ApplyFDOptions in command-line
	// order with lseek / perm-late / async. Do not truncate here; mixed
	// late options keep that order.
	if s.HasOption("ftruncate") {
		return nil
	}
	if s.BoolOption("trunc") {
		if e := f.Truncate(0); e != nil {
			return fmt.Errorf("truncate: %w", e)
		}
	}
	return nil
}

func FileOpened(f *os.File, s parse.Spec, path string) (*xio.Opened, error) {
	// unlink-late runs immediately after open. unlink-close is armed before
	// owner/lock/wrap/termios so a later failure still removes the name.
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
	// OPEN/FILE/GOPEN apply path ownership after open, before descriptor
	// options; CREATE ownership is descriptor-owned and ApplyOwner skips it.
	if err := xio.ApplyOwner(path, s, f); err != nil {
		return fail(err)
	}
	if err := applyFileLocks(s, f, f); err != nil {
		return fail(err)
	}
	// Locks after open must complete before late ftruncate/lseek/async.
	// Applying lifecycle first could mutate the file before a lock failure.
	if err := xio.ApplyFDOptions(f, s); err != nil {
		return fail(err)
	}
	// trunc= after ApplyFDOptions late ftruncate/lseek/perm-late.
	if err := applyOpenTruncate(f, s); err != nil {
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
