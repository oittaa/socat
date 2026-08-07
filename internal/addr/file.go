package addr

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openOPEN(_ context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	if len(s.Params) < 1 {
		return nil, fmt.Errorf("OPEN requires filename")
	}
	path := s.Params[0]
	flags := openFlags(s, mode)
	f, err := os.OpenFile(path, flags, parseFileMode(s, 0o644))
	if err != nil {
		return nil, err
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
	f, err := os.OpenFile(path, flags, parseFileMode(s, 0o644))
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
			f, err := os.OpenFile(path, flags, parseFileMode(s, 0o644))
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
	if !s.BoolOption("append") && mode != ModeRead {
		// classic GOPEN uses O_APPEND when existing non-socket
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(path, flags, parseFileMode(s, 0o644))
	if err != nil {
		return nil, err
	}
	return fileOpened(f, s, path)
}

func openPIPE(_ context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	// Named pipe if param present; else anonymous pipe echo
	if len(s.Params) >= 1 && s.Params[0] != "" {
		path := s.Params[0]
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := syscall.Mkfifo(path, uint32(parseFileMode(s, 0o644))); err != nil {
				return nil, fmt.Errorf("mkfifo %s: %w", path, err)
			}
			o := &Opened{Label: "PIPE:" + path}
			if s.BoolOption("unlink-early") || !s.HasOption("unlink-close") {
				// classic removes named pipe on close by default since 1.4.3
				if !s.HasOption("unlink-close") || s.BoolOption("unlink-close") {
					o.addCleanup(func() { _ = os.Remove(path) })
				}
			}
			flags := openFlags(s, mode)
			f, err := os.OpenFile(path, flags, 0)
			if err != nil {
				o.Close()
				return nil, err
			}
			o.Stream = relay.RWCStream{ReadWriteCloser: f}
			return o, nil
		}
		flags := openFlags(s, mode)
		f, err := os.OpenFile(path, flags, 0)
		if err != nil {
			return nil, err
		}
		return &Opened{Stream: relay.RWCStream{ReadWriteCloser: f}, Label: "PIPE:" + path}, nil
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
	// Stream: read from c1, write to c1 — for SOCK_STREAM socketpair, writing to c1
	// is read from c2, not c1. So we need R=c1 W=c2 for echo... wait:
	// Write to c2 → read from c1. So R=c1, W=c2 gives: data written is readable. Echo!
	return &Opened{
		Stream: relay.FDStream{
			R: c1,
			W: c2,
			C: multiCloser{relay.RWCStream{ReadWriteCloser: c1}, relay.RWCStream{ReadWriteCloser: c2}},
			CloseW: func() error {
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
	var stream relay.Stream
	if s.BoolOption("ignoreeof") {
		stream = relay.FDStream{
			R: newIgnoreEOF(f),
			W: f,
			C: f,
			CloseW: func() error {
				// half-close write not available on regular files
				return nil
			},
		}
	} else {
		stream = relay.RWCStream{ReadWriteCloser: f}
	}
	o := &Opened{
		Stream: stream,
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

