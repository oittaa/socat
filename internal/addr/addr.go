// Package addr implements socat address types and the open/lifecycle API.
package addr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// ErrAcceptTimeout is returned when accept-timeout expires with no connection.
// Classic socat exits 0 in this case (not an error for the process).
var ErrAcceptTimeout = errors.New("accept timeout")

// Mode indicates how an address is used.
type Mode int

const (
	ModeRDWR Mode = iota
	ModeRead
	ModeWrite
)

// IPVersion prefers a particular IP family for ambiguous addresses.
type IPVersion int

const (
	IPvDefault IPVersion = iota // classic -4 default since 1.8.0.1
	IPv4
	IPv6
	IPvAny // -0
)

// Global holds process-wide options affecting address open.
type Global struct {
	Log         *logx.Logger
	IPVersion   IPVersion
	BlockSize   int
	Linger      time.Duration
	Idle        time.Duration
	LeftToRight bool
	RightToLeft bool
	Verbose     bool
	Hex         bool
	Dump        io.Writer
	Statistics  bool
	Sloppy      bool // -s continue on some errors

	// Peer info from the most recently accepted/connected socket (for SOCAT_* env).
	SockAddr  string
	PeerAddr  string
	SockPort  string
	PeerPort  string

	// Child process exit (EXEC/SYSTEM): non-zero promotes socat process exit.
	ChildExitCode int
	ChildErr      error
}

// Opened is a live address endpoint ready for transfer or accept-loop.
type Opened struct {
	Stream   relay.Stream
	Listener net.Listener // non-nil for listen without yet accepting (fork mode parent)
	// AcceptOne blocks until a connection is accepted (non-fork listen).
	// If set, Stream is nil until AcceptOne is used OR Open already accepted.
	// Fork: Listener set, Stream nil.
	// Non-fork listen: Stream is the accepted connection.
	Fork     bool
	Label    string
	cleanup  []func()
	// PeerFilter rejects accepted connections (range/sourceport/lowport).
	// Used by fork accept loops; non-fork applies the same check before returning.
	PeerFilter func(net.Conn) error
	// MaxChildren limits concurrent fork children (0 = unlimited). Classic max-children.
	MaxChildren int
	// For dual: separate read/write streams
	Read  relay.Stream
	Write relay.Stream
}

// Close releases resources.
func (o *Opened) Close() error {
	var first error
	// Prefer cleanup hooks (they own the real FDs). Avoid comparing Stream
	// values: relay.FDStream holds funcs and is not comparable.
	if o.Stream != nil {
		if err := o.Stream.Close(); err != nil && first == nil {
			first = err
		}
		o.Stream = nil
	}
	if o.Listener != nil {
		if err := o.Listener.Close(); err != nil && first == nil {
			first = err
		}
		o.Listener = nil
	}
	for i := len(o.cleanup) - 1; i >= 0; i-- {
		o.cleanup[i]()
	}
	o.cleanup = nil
	o.Read = nil
	o.Write = nil
	return first
}

func (o *Opened) addCleanup(f func()) {
	o.cleanup = append(o.cleanup, f)
}

// EffectiveStream returns the stream used for bidirectional transfer.
func (o *Opened) EffectiveStream() relay.Stream {
	if o.Stream != nil {
		return o.Stream
	}
	if o.Read != nil || o.Write != nil {
		return relay.FDStream{
			R: readerOrEOF(o.Read),
			W: writerOrDiscard(o.Write),
			C: multiCloser{o.Read, o.Write},
			CloseW: func() error {
				if o.Write != nil {
					return o.Write.ShutdownWrite()
				}
				return nil
			},
		}
	}
	return nil
}

type multiCloser struct{ a, b relay.Stream }

func (m multiCloser) Close() error {
	var err error
	if m.a != nil {
		err = m.a.Close()
	}
	if m.b != nil {
		if e := m.b.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func readerOrEOF(s relay.Stream) io.Reader {
	if s != nil {
		return s
	}
	return eofReader{}
}

func writerOrDiscard(s relay.Stream) io.Writer {
	if s != nil {
		return s
	}
	return io.Discard
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// OpenChannel opens a parsed address channel.
func OpenChannel(ctx context.Context, ch parse.Channel, mode Mode, g *Global) (*Opened, error) {
	if ch.IsDual() {
		return openDual(ctx, ch.Dual, g)
	}
	return OpenSpec(ctx, *ch.Single, mode, g)
}

func openDual(ctx context.Context, d *parse.Dual, g *Global) (*Opened, error) {
	left, err := OpenSpec(ctx, d.Left, ModeRead, g)
	if err != nil {
		return nil, fmt.Errorf("dual read side: %w", err)
	}
	right, err := OpenSpec(ctx, d.Right, ModeWrite, g)
	if err != nil {
		left.Close()
		return nil, fmt.Errorf("dual write side: %w", err)
	}
	o := &Opened{
		Read:  left.EffectiveStream(),
		Write: right.EffectiveStream(),
		Label: d.Raw,
	}
	o.addCleanup(func() { left.Close() })
	o.addCleanup(func() { right.Close() })
	// Combine into Stream
	o.Stream = relay.FDStream{
		R: o.Read,
		W: o.Write,
		C: multiCloser{o.Read, o.Write},
		CloseW: func() error {
			return o.Write.ShutdownWrite()
		},
	}
	return o, nil
}

// OpenSpec opens a single address type.
func OpenSpec(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	typ := normalizeType(s.Type)
	s.Type = typ
	openers := map[string]openerFunc{
		"STDIO":        openSTDIO,
		"STDIN":        openSTDIN,
		"STDOUT":       openSTDOUT,
		"STDERR":       openSTDERR,
		"FD":           openFD,
		"PIPE":         openPIPE,
		"FIFO":         openPIPE,
		"ECHO":         openPIPE, // classic synonym for unnamed/named pipe echo
		"OPEN":         openOPEN,
		"FILE":         openOPEN, // classic synonym
		"CREATE":       openCREATE,
		"CREAT":        openCREATE, // classic short form
		"GOPEN":        openGOPEN,
		"TCP":           openTCPConnect,
		"TCP4":          openTCP4Connect,
		"TCP6":          openTCP6Connect,
		"TCP-CONNECT":   openTCPConnect,
		"TCP4-CONNECT":  openTCP4Connect,
		"TCP6-CONNECT":  openTCP6Connect,
		"TCP-LISTEN":    openTCPListen,
		"TCP4-LISTEN":   openTCP4Listen,
		"TCP6-LISTEN":   openTCP6Listen,
		"TCP-L":         openTCPListen,
		"TCP4-L":        openTCP4Listen,
		"TCP6-L":        openTCP6Listen,
		"UDP":           openUDPConnect,
		"UDP4":          openUDP4Connect,
		"UDP6":          openUDP6Connect,
		"UDP-CONNECT":   openUDPConnect,
		"UDP4-CONNECT":  openUDP4Connect,
		"UDP6-CONNECT":  openUDP6Connect,
		"UDP-LISTEN":   openUDPListen,
		"UDP4-LISTEN":  openUDP4Listen,
		"UDP6-LISTEN":  openUDP6Listen,
		"UDP-L":        openUDPListen,
		"UDP4-L":       openUDP4Listen,
		"UDP6-L":       openUDP6Listen,
		"UDP-SENDTO":   openUDPSendto,
		"UDP4-SENDTO":  openUDP4Sendto,
		"UDP6-SENDTO":  openUDP6Sendto,
		"UDP-SEND":     openUDPSendto,
		"UDP4-SEND":    openUDP4Sendto,
		"UDP6-SEND":    openUDP6Sendto,
		"UDP-DATAGRAM": openUDPDatagram,
		"UDP4-DATAGRAM": openUDP4Datagram,
		"UDP6-DATAGRAM": openUDP6Datagram,
		"UDP-RECV":     openUDPRecv,
		"UDP4-RECV":    openUDP4Recv,
		"UDP6-RECV":    openUDP6Recv,
		"UDP-RECVFROM": openUDPRecvfrom,
		"UDP4-RECVFROM": openUDP4Recvfrom,
		"UDP6-RECVFROM": openUDP6Recvfrom,
		"UNIX":          openUnixConnect,
		"UNIX-CONNECT":  openUnixConnect,
		"UNIX-CLIENT":   openUnixConnect,
		"UNIX-LISTEN":   openUnixListen,
		"UNIX-L":        openUnixListen,
		"UNIX-SENDTO":   openUnixSendto,
		"UNIX-RECVFROM": openUnixRecvfrom,
		"UNIX-RECV":     openUnixRecv,
		"UNIX-DATAGRAM": openUnixDatagram,
		// Linux abstract namespace (path becomes abstract name).
		"ABSTRACT-CLIENT":  openAbstractSendto,
		"ABSTRACT-CONNECT": openAbstractSendto,
		"ABSTRACT-SENDTO":  openAbstractSendto,
		"ABSTRACT-RECVFROM": openAbstractSendto, // minimal: same dial path for bind tests
		"ABSTRACT-RECV":    openAbstractSendto,
		"SOCKETPAIR":       openSocketpair,
		"SOCKET-CONNECT":   openSocketConnect,
		"SOCKET-LISTEN":    openSocketListen,
		"SOCKET-SENDTO":    openSocketSendto,
		"SOCKET-DATAGRAM":  openSocketDatagram,
		"SOCKET-RECV":      openSocketRecv,
		"SOCKET-RECVFROM":  openSocketRecvfrom,
		"EXEC":         openEXEC,
		"SYSTEM":       openSYSTEM,
		"SHELL":        openSHELL,
		"TEXT":         openTEXT,
		"STALL":        openSTALL,
		"PTY":          openPTY,
	}
	fn, ok := openers[typ]
	if !ok {
		// Message text must match classic for test.sh testaddrs():
		// grep "E unknown device/address"
		return nil, fmt.Errorf("unknown device/address \"%s\"", s.Type)
	}
	return fn(ctx, s, mode, g)
}

type openerFunc func(context.Context, parse.Spec, Mode, *Global) (*Opened, error)

func normalizeType(t string) string {
	t = strings.ToUpper(t)
	// synonyms already uppercased
	return t
}

// Run is the top-level socat transfer between two channels.
func Run(ctx context.Context, left, right parse.Channel, g *Global) error {
	// Determine modes from -u/-U
	lMode, rMode := ModeRDWR, ModeRDWR
	if g.LeftToRight && !g.RightToLeft {
		lMode, rMode = ModeRead, ModeWrite
	} else if g.RightToLeft && !g.LeftToRight {
		lMode, rMode = ModeWrite, ModeRead
	}

	// Open left first (classic order)
	lo, err := OpenChannel(ctx, left, lMode, g)
	if err != nil {
		// Preserve classic "unknown device/address" text for test.sh testaddrs().
		return err
	}
	defer lo.Close()

	// Fork listen on left: accept loop
	if lo.Fork && lo.Listener != nil {
		return runForkListen(ctx, lo, right, rMode, g)
	}

	ro, err := OpenChannel(ctx, right, rMode, g)
	if err != nil {
		return err
	}
	defer ro.Close()

	if ro.Fork && ro.Listener != nil {
		// Unusual: listen on right — classic still works; handle accept loop with left already open
		return runForkListenRight(ctx, lo, ro, g)
	}

	return transferPair(ctx, lo, ro, g)
}

func runForkListen(ctx context.Context, lo *Opened, right parse.Channel, rMode Mode, g *Global) error {
	ln := lo.Listener
	g.Log.Noticef("listening on %s", ln.Addr())
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	filter := lo.PeerFilter
	maxCh := lo.MaxChildren
	// Semaphore for max-children (0 = unlimited).
	var slots chan struct{}
	if maxCh > 0 {
		slots = make(chan struct{}, maxCh)
	}
	for {
		if slots != nil {
			select {
			case <-ctx.Done():
				return nil
			case slots <- struct{}{}:
			}
		}
		conn, err := ln.Accept()
		if err != nil {
			if slots != nil {
				<-slots
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if filter != nil {
			if err := filter(conn); err != nil {
				g.Log.Noticef("%s", err)
				conn.Close()
				if slots != nil {
					<-slots
				}
				continue
			}
		}
		g.Log.Infof("accepted %s", conn.RemoteAddr())
		go func(c net.Conn) {
			defer c.Close()
			if slots != nil {
				defer func() { <-slots }()
			}
			// Per-connection Global copy so SOCAT_* env is correct under concurrency.
			cg := *g
			rememberAddrs(&cg, c)
			leftStream := relay.Stream(relay.NetStream{Conn: c})
			ro, err := OpenChannel(ctx, right, rMode, &cg)
			if err != nil {
				g.Log.Errorf("right address: %s", err)
				return
			}
			defer ro.Close()
			if err := transferStreams(ctx, leftStream, ro.EffectiveStream(), &cg); err != nil {
				g.Log.Debugf("transfer: %s", err)
			}
		}(conn)
	}
}

func runForkListenRight(ctx context.Context, lo, ro *Opened, g *Global) error {
	ln := ro.Listener
	left := lo.EffectiveStream()
	// Shared left (e.g. FILE,o-append) must stay open across all fork children.
	// Classic max-children + -U FILE:... LISTEN,fork appends each session in order.
	// max-children applies to the listen address (right side here).
	maxCh := ro.MaxChildren
	var slots chan struct{}
	if maxCh > 0 {
		slots = make(chan struct{}, maxCh)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	filter := ro.PeerFilter
	for {
		if slots != nil {
			select {
			case <-ctx.Done():
				return nil
			case slots <- struct{}{}:
			}
		}
		conn, err := ln.Accept()
		if err != nil {
			if slots != nil {
				<-slots
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if filter != nil {
			if err := filter(conn); err != nil {
				g.Log.Noticef("%s", err)
				conn.Close()
				if slots != nil {
					<-slots
				}
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			if slots != nil {
				defer func() { <-slots }()
			}
			cg := *g
			rememberAddrs(&cg, c)
			rightStream := relay.NetStream{Conn: c}
			// noCloseLeft=true: do not close/shutdown shared left between children.
			if err := transferStreamsOpts(ctx, left, rightStream, &cg, true, false); err != nil {
				g.Log.Debugf("transfer: %s", err)
			}
		}(conn)
	}
}

func transferPair(ctx context.Context, lo, ro *Opened, g *Global) error {
	return transferStreams(ctx, lo.EffectiveStream(), ro.EffectiveStream(), g)
}

func transferStreams(ctx context.Context, left, right relay.Stream, g *Global) error {
	return transferStreamsOpts(ctx, left, right, g, streamIsEndClose(left), streamIsEndClose(right))
}

func transferStreamsOpts(ctx context.Context, left, right relay.Stream, g *Global, noCloseLeft, noCloseRight bool) error {
	if left == nil || right == nil {
		return fmt.Errorf("nil stream")
	}
	cfg := relay.Config{
		BufferSize:   g.BlockSize,
		Linger:       g.Linger,
		IdleTimeout:  g.Idle,
		LeftToRight:  g.LeftToRight || (!g.LeftToRight && !g.RightToLeft),
		RightToLeft:  g.RightToLeft || (!g.LeftToRight && !g.RightToLeft),
		Verbose:      g.Verbose,
		Hex:          g.Hex,
		Dump:         g.Dump,
		NoCloseLeft:  noCloseLeft,
		NoCloseRight: noCloseRight,
	}
	if !g.LeftToRight && !g.RightToLeft {
		cfg.LeftToRight = true
		cfg.RightToLeft = true
	} else {
		cfg.LeftToRight = g.LeftToRight
		cfg.RightToLeft = g.RightToLeft
	}
	if g.Statistics {
		cfg.OnStats = func(st relay.Stats) {
			g.Log.Noticef("stats: lr=%d bytes/%d blocks rl=%d bytes/%d blocks duration=%s",
				st.BytesLR, st.BlocksLR, st.BytesRL, st.BlocksRL, st.Duration)
		}
	}
	return relay.Transfer(ctx, left, right, cfg)
}

// Apply common file mode from options (octal string).
func parseFileMode(s parse.Spec, def os.FileMode) os.FileMode {
	v := s.OptionValue("mode", "")
	if v == "" {
		return def
	}
	var m uint64
	_, err := fmt.Sscanf(v, "%o", &m)
	if err != nil {
		return def
	}
	return os.FileMode(m)
}
