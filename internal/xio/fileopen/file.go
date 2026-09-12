package fileopen

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
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
func openUserFileWithUmask(config addrconfig.File, path string, flags int, perm os.FileMode) (*os.File, error) {
	var f *os.File
	err := xio.WithConfiguredUmask(config, func() error {
		var e error
		f, e = openUserFile(path, flags, perm)
		return e
	})
	return f, err
}

func openOPEN(ctx context.Context, s addrconfig.Address, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("OPEN requires filename")
	}
	path := s.Params[0]
	flags, err := ConfiguredOpenFlags(s.File, mode)
	if err != nil {
		return nil, err
	}
	perm := xio.ConfiguredFileMode(s.File, xio.DefaultCreateMode)
	if _, err := namedOpenEarly(path, s.File); err != nil {
		return nil, err
	}
	f, err := openUserFileWithUmask(s.File, path, flags, perm)
	if err != nil {
		// Error text is open("path", …) so RECVFROM_FORK_LOOP parsers match it.
		return nil, fmt.Errorf("open(%q, %02o, %04o): %w", path, flags, xio.FileModeToUnix(perm), err)
	}
	return FileOpened(f, s, path)
}

func openCREATE(ctx context.Context, s addrconfig.Address, mode xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("CREATE requires filename")
	}
	if mode == xio.ModeRead {
		return nil, fmt.Errorf("CREATE is write-only")
	}
	path := s.Params[0]
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if s.File.Append {
		// CREATE uses creat(2) semantics (always truncates first). append is
		// late; O_TRUNC|O_APPEND has the same descriptor semantics without
		// preserving stale contents.
		flags |= os.O_APPEND
	}
	// CREATE does not take open(2) flags (o-direct, o-sync, …); those are
	// rejected at option validation rather than applied here.
	perm := xio.ConfiguredFileMode(s.File, xio.DefaultCreateMode)
	if _, err := namedOpenEarly(path, s.File); err != nil {
		return nil, err
	}
	f, err := openUserFileWithUmask(s.File, path, flags, perm)
	if err != nil {
		return nil, err
	}
	return FileOpened(f, s, path)
}

func openGOPEN(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("GOPEN requires filename")
	}
	path := s.Params[0]
	early, err := namedOpenEarly(path, s.File)
	if err != nil {
		return nil, err
	}
	if !early.exists {
		// create regular file
		flags, ferr := ConfiguredOpenFlags(s.File, mode)
		if ferr != nil {
			return nil, ferr
		}
		flags |= os.O_CREATE
		perm := xio.ConfiguredFileMode(s.File, xio.DefaultCreateMode)
		f, err := openUserFileWithUmask(s.File, path, flags, perm)
		if err != nil {
			return nil, err
		}
		return FileOpened(f, s, path)
	}
	// UNIX domain socket? Uses the pre-unlink os.Stat snapshot: unlink
	// after the name exists, before open, does not reclassify a socket as
	// a missing create-path.
	if early.mode&os.ModeSocket != 0 {
		if err := rejectGOPENSocketOpenFlags(s.File); err != nil {
			return nil, err
		}
		// UNIX generic client probes stream, seqpacket, then datagram.
		o, err := xio.OpenWithType(ctx, "UNIX", s, mode, g)
		if err != nil {
			return nil, err
		}
		// GOPEN of a socket applies unlink-late after connect; unlink-close
		// is only armed for non-sockets.
		if err := applyNamedUnlinkLate(path, s.File); err != nil {
			logx.CloseQuiet(o)
			return nil, err
		}
		return o, nil
	}
	flags, err := ConfiguredOpenFlags(s.File, mode)
	if err != nil {
		return nil, err
	}
	// GOPEN defaults to O_APPEND on existing regular files only.
	// Devices (PTY slaves via FAKEPTY link=), fifos, etc. must not get O_APPEND.
	isReg := early.mode.IsRegular()
	if mode != xio.ModeRead && isReg {
		if s.File.AppendSet {
			if s.File.Append {
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
	perm := xio.ConfiguredFileMode(s.File, xio.DefaultCreateMode)
	f, err := openUserFile(path, flags, perm)
	if err != nil {
		return nil, err
	}
	return FileOpened(f, s, path)
}

func openPIPE(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Named pipe if param present; else anonymous pipe echo
	if len(s.Params) >= 1 && s.Params[0] != "" {
		return openNamedPIPE(s, mode)
	}
	if err := rejectUnnamedPIPEOpenFlags(s.File); err != nil {
		return nil, err
	}

	// Anonymous pipe echo: writes to the write end are readable on the read end.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	if err := xio.ApplyConfiguredFDOptions(r, s.File, xio.FDSkip{}); err != nil {
		logx.CloseQuiet(r)
		logx.CloseQuiet(w)
		return nil, err
	}
	if err := xio.ApplyConfiguredFDOptions(w, s.File, xio.FDSkip{}); err != nil {
		logx.CloseQuiet(r)
		logx.CloseQuiet(w)
		return nil, err
	}
	st, err := xio.WrapAfterFD(s, relay.FDStream{
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
func openNamedPIPE(config addrconfig.Address, mode xio.Mode) (*xio.Opened, error) {
	p, err := prepareNamedPIPE(config)
	if err != nil {
		return nil, err
	}
	switch mode {
	case xio.ModeRead:
		return p.openRead()
	case xio.ModeWrite:
		return p.openWrite()
	default:
		return p.openBidir()
	}
}

type namedPIPE struct {
	config     addrconfig.Address
	path       string
	created    bool
	doUnlink   bool
	unregister func()
}

func prepareNamedPIPE(config addrconfig.Address) (*namedPIPE, error) {
	path := config.Params[0]
	// unlink-early unlinks even when the name is missing; ENOENT aborts
	// before mkfifo. OPEN / CREATE / GOPEN instead share namedOpenEarly
	// (exists && unlink-early).
	if config.File.UnlinkEarly.Value {
		if err := xio.Unlink(path); err != nil {
			return nil, fmt.Errorf("unlink %s: %w", path, err)
		}
	}
	// perm-early / user-early / group-early / unlink in command-line order
	// when the name still exists after unlink-early.
	if _, err := namedOpenEarly(path, config.File); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := xio.WithConfiguredUmask(config.File, func() error {
			return mkfifo(path, xio.FileModeToUnix(xio.ConfiguredFileMode(config.File, xio.DefaultCreateMode)))
		})
		if err != nil {
			return nil, fmt.Errorf("mkfifo %s: %w", path, err)
		}
		created = true
	}
	// Ownership applies to a newly created FIFO immediately, but to an
	// existing FIFO only after open succeeds.
	if created {
		if err := xio.ApplyConfiguredOwner(path, config.Facts.Kind, nil, config.File); err != nil {
			_ = xio.Unlink(path)
			return nil, err
		}
	}
	// After mkfifo, before the possibly blocking open, register unlink-close
	// so SIGTERM removes the FIFO. Only the creating process unlinks;
	// unlink-close=0 keeps the entry.
	doUnlink := created && (!config.File.UnlinkClose.Set || config.File.UnlinkClose.Value)
	unregister := func() {}
	if doUnlink {
		unregister = xio.RegisterUnlinkPath(path)
	}
	return &namedPIPE{config: config, path: path, created: created, doUnlink: doUnlink, unregister: unregister}, nil
}

func (p *namedPIPE) applyExistingOwner() error {
	if p.created {
		return nil
	}
	return xio.ApplyConfiguredOwner(p.path, p.config.Facts.Kind, nil, p.config.File)
}

func (p *namedPIPE) removeCreated() {
	if p.created {
		p.unregister()
		_ = xio.Unlink(p.path)
	}
}

func (p *namedPIPE) failOpen(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			logx.CloseQuiet(f)
		}
	}
	p.removeCreated()
}

func (p *namedPIPE) addPathCleanup(o *xio.Opened) {
	if !p.doUnlink {
		return
	}
	unregister, path := p.unregister, p.path
	o.AddCleanup(func() {
		unregister()
		_ = xio.Unlink(path)
	})
}

func (p *namedPIPE) applyAfterOpen(files ...*os.File) error {
	if err := p.applyExistingOwner(); err != nil {
		return err
	}
	if err := applyNamedUnlinkLate(p.path, p.config.File); err != nil {
		return err
	}
	for _, f := range files {
		if err := xio.ApplyConfiguredFDOptions(f, p.config.File, xio.FDSkipOwner); err != nil {
			return err
		}
	}
	return nil
}

func (p *namedPIPE) wrapFile(f *os.File) (*xio.Opened, error) {
	st, err := xio.WrapAfterFD(p.config, xio.FileStream(f))
	if err != nil {
		p.failOpen(f)
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "PIPE:" + p.path}
	p.addPathCleanup(o)
	return o, nil
}

func (p *namedPIPE) openRead() (*xio.Opened, error) {
	// Explicit nonblock lets the read side of a dual PIPE open before its
	// write side. Otherwise, wait for a writer so the first Read cannot see
	// a premature EOF before the peer opens the FIFO.
	flags := os.O_RDONLY
	if p.config.File.Nonblock {
		flags |= oNonblock
	}
	f, err := openConfiguredFIFO(p.path, flags, p.config.File)
	if err != nil {
		p.removeCreated()
		return nil, err
	}
	if err := p.applyAfterOpen(f); err != nil {
		p.failOpen(f)
		return nil, err
	}
	return p.wrapFile(f)
}

func (p *namedPIPE) openWrite() (*xio.Opened, error) {
	// Need a reader end open first for O_WRONLY on FIFO. The dummy reader
	// is not an address fd; o-direct applies only to the user-facing writer.
	r, err := openUserFile(p.path, os.O_RDONLY|oNonblock, 0)
	if err != nil {
		p.removeCreated()
		return nil, err
	}
	w, err := openConfiguredFIFO(p.path, os.O_WRONLY|oNonblock, p.config.File)
	if err != nil {
		logx.CloseQuiet(r)
		p.removeCreated()
		return nil, err
	}
	clearNonblock(w)
	logx.CloseQuiet(r)
	if err := p.applyAfterOpen(w); err != nil {
		p.failOpen(w)
		return nil, err
	}
	return p.wrapFile(w)
}

func (p *namedPIPE) openBidir() (*xio.Opened, error) {
	// Bidirectional: open reader then writer (both NONBLOCK), then blocking I/O.
	r, err := openConfiguredFIFO(p.path, os.O_RDONLY|oNonblock, p.config.File)
	if err != nil {
		p.removeCreated()
		return nil, err
	}
	w, err := openConfiguredFIFO(p.path, os.O_WRONLY|oNonblock, p.config.File)
	if err != nil {
		logx.CloseQuiet(r)
		p.removeCreated()
		return nil, err
	}
	clearNonblock(r)
	clearNonblock(w)
	if err := p.applyAfterOpen(r, w); err != nil {
		p.failOpen(r, w)
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
	st, err := xio.WrapAfterFD(p.config, stream)
	if err != nil {
		p.failOpen(r, w)
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: "PIPE:" + p.path}
	o.AddCleanup(func() { logx.CloseQuiet(r); logx.CloseQuiet(w) })
	p.addPathCleanup(o)
	return o, nil
}

func openSocketpair(_ context.Context, s addrconfig.Address, _ xio.Mode, _ *xio.Global) (*xio.Opened, error) {
	// Standalone SOCKETPAIR defaults to SOCK_DGRAM. EXEC/SYSTEM still
	// request SOCK_STREAM for their internal pair.
	typ, _, err := xio.SocketTypeOption(s, syscall.SOCK_DGRAM)
	if err != nil {
		return nil, err
	}
	c1, c2, err := socketpairFiles(typ)
	if err != nil {
		return nil, err
	}
	for _, conn := range []*os.File{c1, c2} {
		// SOCKETPAIR is not phase-grouped: apply every named or generic
		// setsockopt action once per fd in original option order (broadcast,
		// sndbuf, linger, timeos, connected-phase options, …).
		// ApplySocketOptions is past-socket only and would drop connected-phase
		// options.
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
	st, err := xio.SetupConnectedStream(s, stream)
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

func openConfiguredFIFO(path string, flags int, config addrconfig.File) (*os.File, error) {
	flags, err := configuredOpenFlags(config, flags)
	if err != nil {
		return nil, err
	}
	return openUserFile(path, flags, 0)
}

func applyConfiguredOpenTruncate(f *os.File, config addrconfig.File) error {
	// ftruncate is late and is applied by ApplyFDOptions in command-line
	// order with lseek / perm-late / async. Do not truncate here; mixed
	// late options keep that order.
	for _, action := range config.Actions {
		if action.Kind == addrconfig.FileActionTruncate {
			return nil
		}
	}
	if config.Truncate {
		if e := f.Truncate(0); e != nil {
			return fmt.Errorf("truncate: %w", e)
		}
	}
	return nil
}

func FileOpened(f *os.File, config addrconfig.Address, path string) (*xio.Opened, error) {
	// unlink-late runs immediately after open. unlink-close is armed before
	// owner/lock/wrap/termios so a later failure still removes the name.
	guard, err := namedAfterOpen(path, config.File)
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
	if err := xio.ApplyConfiguredOwner(path, config.Facts.Kind, f, config.File); err != nil {
		return fail(err)
	}
	if err := applyConfiguredFileLocks(config.File, f, f); err != nil {
		return fail(err)
	}
	// Locks after open must complete before late ftruncate/lseek/async.
	// Applying lifecycle first could mutate the file before a lock failure.
	if err := xio.ApplyConfiguredFDOptions(f, config.File, namedOpenFDSkip(config.Facts.Kind)); err != nil {
		return fail(err)
	}
	// trunc= after ApplyFDOptions late ftruncate/lseek/perm-late.
	if err := applyConfiguredOpenTruncate(f, config.File); err != nil {
		return fail(err)
	}
	st, err := xio.WrapAfterFD(config, xio.FileStream(f))
	if err != nil {
		return fail(err)
	}
	o := &xio.Opened{
		Stream: st,
		Label:  path,
	}
	if err := xio.AttachConfiguredTermios(o, int(f.Fd()), config.Terminal); err != nil {
		return fail(err)
	}
	guard.attach(o)
	return o, nil
}

func namedOpenFDSkip(kind addrconfig.AddressKind) xio.FDSkip {
	if kind == addrconfig.AddressKindCREATE {
		return xio.FDSkipCREATE
	}
	return xio.FDSkipNamedFile
}
