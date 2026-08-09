package addr

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func openOPEN(_ context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("OPEN requires filename")
	}
	path := s.Params[0]
	flags := openFlags(s, mode)
	var f *os.File
	err := withUmask(s, func() error {
		var e error
		f, e = os.OpenFile(path, flags, parseFileMode(s, 0o644))
		return e
	})
	if err != nil {
		// Classic format for RECVFROM_FORK_LOOP: `E open("path", …): …`
		return nil, fmt.Errorf("open(%q, %02o, %04o): %w", path, flags, parseFileMode(s, 0o666), err)
	}
	if s.HasOption("ftruncate") || s.HasOption("trunc") {
		// ftruncate=N or trunc flag after open
		if v := s.OptionValue("ftruncate", ""); v != "" {
			var n int64
			if _, e := fmt.Sscanf(v, "%d", &n); e == nil {
				_ = f.Truncate(n)
			}
		} else if s.BoolOption("trunc") {
			_ = f.Truncate(0)
		}
	}
	return fileOpened(f, s, path)
}

func openCREATE(_ context.Context, s parse.Spec, mode Mode, _ *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("CREATE requires filename")
	}
	if mode == ModeRead {
		return nil, fmt.Errorf("CREATE is write-only")
	}
	path := s.Params[0]
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if s.BoolOption("append") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	var f *os.File
	err := withUmask(s, func() error {
		var e error
		f, e = os.OpenFile(path, flags, parseFileMode(s, 0o644))
		return e
	})
	if err != nil {
		return nil, err
	}
	return fileOpened(f, s, path)
}

func openGOPEN(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("GOPEN requires filename")
	}
	path := s.Params[0]
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// create regular file
			flags := os.O_RDWR | os.O_CREATE
			if mode == ModeRead {
				flags = os.O_RDONLY | os.O_CREATE
			} else if mode == ModeWrite {
				flags = os.O_WRONLY | os.O_CREATE
			}
			var f *os.File
			err := withUmask(s, func() error {
				var e error
				f, e = os.OpenFile(path, flags, parseFileMode(s, 0o644))
				return e
			})
			if err != nil {
				return nil, err
			}
			return fileOpened(f, s, path)
		}
		return nil, err
	}
	// UNIX domain socket?
	if fi.Mode()&os.ModeSocket != 0 {
		return openUnixConnect(ctx, parse.Spec{
			Type:    "UNIX-CONNECT",
			Params:  []string{path},
			Options: s.Options,
			Raw:     s.Raw,
		}, mode, g)
	}
	flags := openFlags(s, mode)
	// Classic GOPEN defaults to O_APPEND on existing regular files only.
	// Devices (PTY slaves via FAKEPTY link=), fifos, etc. must not get O_APPEND.
	isReg := fi.Mode().IsRegular()
	if mode != ModeRead && isReg {
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
	f, err := os.OpenFile(path, flags, parseFileMode(s, 0o644))
	if err != nil {
		return nil, err
	}
	if s.BoolOption("cfmakeraw") || s.HasOption("cfmakeraw") {
		if err := setRaw(int(f.Fd())); err != nil {
			f.Close()
			return nil, fmt.Errorf("cfmakeraw: %w", err)
		}
	}
	return fileOpened(f, s, path)
}

func openPIPE(_ context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	// Named pipe if param present; else anonymous pipe echo
	if len(s.Params) >= 1 && s.Params[0] != "" {
		return openNamedPIPE(s, mode)
	}

	// Anonymous pipe echo: writes to the write end are readable on the read end.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	return &Opened{
		Stream: relay.FDStream{
			R: r,
			W: w,
			C: multiCloser{relay.RWCStream{ReadWriteCloser: r}, relay.RWCStream{ReadWriteCloser: w}},
			CloseW: func() error {
				return w.Close()
			},
		},
		Label: "PIPE",
		cleanup: []func(){
			func() { r.Close(); w.Close() },
		},
	}, nil
}

// openNamedPIPE creates/opens a FIFO. For bidirectional use we open separate
// read and write FDs so ShutdownWrite can close the writer and deliver EOF.
func openNamedPIPE(s parse.Spec, mode Mode) (*Opened, error) {
	path := s.Params[0]
	created := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := withUmask(s, func() error {
			return syscall.Mkfifo(path, uint32(parseFileMode(s, 0o644)))
		})
		if err == nil {
			_ = applyPerm(path, s, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("mkfifo %s: %w", path, err)
		}
		created = true
	}

	cleanupPath := func() {
		if created || s.BoolOption("unlink-close") || !s.HasOption("unlink-close") {
			if s.BoolOption("unlink-early") {
				return
			}
			if !s.HasOption("unlink-close") || s.BoolOption("unlink-close") {
				_ = os.Remove(path)
			}
		}
	}

	clearNB := func(f *os.File) {
		fd := int(f.Fd())
		fl, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if e == nil {
			_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl&^unix.O_NONBLOCK)
		}
	}

	switch mode {
	case ModeRead:
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		clearNB(f)
		if s.BoolOption("unlink-early") {
			_ = os.Remove(path)
		}
		st, err := wrapCommon(s, fileStream(f))
		if err != nil {
			f.Close()
			return nil, err
		}
		o := &Opened{Stream: st, Label: "PIPE:" + path}
		if !s.BoolOption("unlink-early") {
			o.addCleanup(cleanupPath)
		}
		return o, nil
	case ModeWrite:
		// Need a reader end open first for O_WRONLY on FIFO.
		r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			r.Close()
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		clearNB(w)
		r.Close() // only writing
		if s.BoolOption("unlink-early") {
			_ = os.Remove(path)
		}
		st, err := wrapCommon(s, fileStream(w))
		if err != nil {
			w.Close()
			return nil, err
		}
		o := &Opened{Stream: st, Label: "PIPE:" + path}
		if !s.BoolOption("unlink-early") {
			o.addCleanup(cleanupPath)
		}
		return o, nil
	default:
		// Bidirectional: open reader then writer (both NONBLOCK), then blocking I/O.
		r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			r.Close()
			if created {
				_ = os.Remove(path)
			}
			return nil, err
		}
		clearNB(r)
		clearNB(w)
		if s.BoolOption("unlink-early") {
			_ = os.Remove(path)
		}
		stream := relay.FDStream{
			R: r,
			W: w,
			C: multiCloser{relay.RWCStream{ReadWriteCloser: r}, relay.RWCStream{ReadWriteCloser: w}},
			CloseW: func() error {
				return w.Close()
			},
		}
		st, err := wrapCommon(s, stream)
		if err != nil {
			r.Close()
			w.Close()
			return nil, err
		}
		o := &Opened{Stream: st, Label: "PIPE:" + path}
		o.addCleanup(func() { r.Close(); w.Close() })
		if !s.BoolOption("unlink-early") {
			o.addCleanup(cleanupPath)
		}
		return o, nil
	}
}

func openSocketpair(_ context.Context, _ parse.Spec, _ Mode, _ *Global) (*Opened, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
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

	c1 := os.NewFile(uintptr(fds[0]), "socketpair0")
	c2 := os.NewFile(uintptr(fds[1]), "socketpair1")
	// Echo: write to c2 is readable on c1.
	return &Opened{
		Stream: relay.FDStream{
			R: c1,
			W: c2,
			C: multiCloser{relay.RWCStream{ReadWriteCloser: c1}, relay.RWCStream{ReadWriteCloser: c2}},
			CloseW: func() error {
				_ = unix.Shutdown(int(c2.Fd()), unix.SHUT_WR)
				return c2.Close()
			},
		},
		Label: "SOCKETPAIR",
		cleanup: []func(){
			func() { c1.Close(); c2.Close() },
		},
	}, nil
}

func openFlags(s parse.Spec, mode Mode) int {
	var flags int
	switch mode {
	case ModeRead:
		flags = os.O_RDONLY
	case ModeWrite:
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
		flags |= syscall.O_NONBLOCK
	}
	return flags
}

func fileOpened(f *os.File, s parse.Spec, path string) (*Opened, error) {
	// Classic perm=/mode= via fchmod after open (CREATE_PERM etc.).
	if err := applyPerm(path, s, f); err != nil {
		f.Close()
		return nil, err
	}
	var stream relay.Stream
	if s.BoolOption("ignoreeof") {
		stream = relay.FDStream{
			R: newIgnoreEOF(f),
			W: f,
			C: f,
			CloseW: func() error {
				return nil
			},
		}
	} else {
		stream = fileStream(f)
	}
	st, err := wrapCommon(s, stream)
	if err != nil {
		f.Close()
		return nil, err
	}
	o := &Opened{
		Stream: st,
		Label:  path,
	}
	if s.BoolOption("unlink-early") {
		_ = os.Remove(path)
	}
	if s.BoolOption("unlink-late") || s.BoolOption("unlink-close") {
		o.addCleanup(func() { _ = os.Remove(path) })
	}
	return o, nil
}

