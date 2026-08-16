package xio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	Log          *logx.Logger
	IPVersion    IPVersion
	BlockSize    int
	Linger       time.Duration
	Idle         time.Duration
	LeftToRight  bool
	RightToLeft  bool
	Verbose      bool
	Hex          bool
	Dump         io.Writer
	Statistics   bool
	statsPrinted atomic.Bool
	Sloppy       bool // -s continue on some errors

	// Peer info from the most recently accepted/connected socket (for SOCAT_* env).
	SockAddr string
	PeerAddr string
	SockPort string
	PeerPort string

	// TLS peer certificate fields (classic SOCAT_OPENSSL_X509_*).
	TLSPeerSubject    string
	TLSPeerIssuer     string
	TLSPeerCommonName string
	TLSPeerCountry    string
	TLSPeerLocality   string
	TLSPeerOrg        string
	TLSPeerOrgUnit    string

	// Child process exit (EXEC/SYSTEM): non-zero promotes socat process exit.
	ChildExitCode int
	ChildErr      error

	// Classic -r / -R raw transfer dumps (left→right / right→left).
	// Path templates may contain $PROGNAME, $TIMESTAMP, $MICROS, $$, $ENV.
	// Files are opened at transfer start (after peer is known) with CLOEXEC.
	RawLeftPath  string
	RawRightPath string
	Progname     string // -lp value; default "socat"
	RawLeft      *os.File
	RawRight     *os.File
}

// Opened is a live address endpoint ready for transfer or accept-loop.
type Opened struct {
	Stream   relay.Stream
	Listener net.Listener // non-nil for listen without yet accepting (fork mode parent)
	// AcceptOne blocks until a connection is accepted (non-fork listen).
	// If set, Stream is nil until AcceptOne is used OR Open already accepted.
	// Fork: Listener set, Stream nil.
	// Non-fork listen: Stream is the accepted connection.
	Fork    bool
	Label   string
	Cleanup []func()
	// PeerFilter rejects accepted connections (range/sourceport/lowport).
	// Used by fork accept loops; non-fork applies the same check before returning.
	PeerFilter func(net.Conn) error
	// MaxChildren limits concurrent fork children (0 = unlimited). Classic max-children.
	MaxChildren int
	// ConnectFork: client-side reconnect loop (TCP/TLS/SOCKS/PROXY CONNECT with fork).
	// Parent dials repeatedly; each child transfers one connection. Dial must
	// complete the full open (including TLS/SOCKS/HTTP handshake).
	ConnectFork bool
	Dial        func(ctx context.Context) (net.Conn, error)
	// WrapDial wraps each dialed conn for transfer (crlf, escape, …). Optional.
	WrapDial func(net.Conn) (relay.Stream, error)
	// Interval between parent connect iterations (classic interval= seconds).
	Interval time.Duration
	// For dual: separate read/write streams
	Read  relay.Stream
	Write relay.Stream
	// NoForkSpec: EXEC/SYSTEM,nofork — process started in Run with peer FD as stdio.
	NoForkSpec *parse.Spec
	// ttyRestore runs before Stream.Close so termios restore still sees the fd.
	ttyRestore []func()
}

// Close releases resources.
func (o *Opened) Close() error {
	var first error
	for i := len(o.ttyRestore) - 1; i >= 0; i-- {
		o.ttyRestore[i]()
	}
	o.ttyRestore = nil
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
	for i := len(o.Cleanup) - 1; i >= 0; i-- {
		o.Cleanup[i]()
	}
	o.Cleanup = nil
	o.Read = nil
	o.Write = nil
	return first
}

func (o *Opened) AddCleanup(f func()) {
	o.Cleanup = append(o.Cleanup, f)
}

// AddTTYRestore runs before the stream FD is closed.
func (o *Opened) AddTTYRestore(f func()) {
	o.ttyRestore = append(o.ttyRestore, f)
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
			C: NewMultiCloser(o.Read, o.Write),
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

// MultiCloser closes two streams.
type MultiCloser struct{ a, b relay.Stream }

// NewMultiCloser returns a closer for two streams.
func NewMultiCloser(a, b relay.Stream) MultiCloser {
	return MultiCloser{a: a, b: b}
}

func (m MultiCloser) Close() error {
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
	return EOFReader{}
}

func writerOrDiscard(s relay.Stream) io.Writer {
	if s != nil {
		return s
	}
	return io.Discard
}

type EOFReader struct{}

func (EOFReader) Read([]byte) (int, error) { return 0, io.EOF }

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
	o.AddCleanup(func() { left.Close() })
	o.AddCleanup(func() { right.Close() })
	// Combine into Stream
	o.Stream = relay.FDStream{
		R: o.Read,
		W: o.Write,
		C: NewMultiCloser(o.Read, o.Write),
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
	fn, ok := lookupOpener(typ)
	if !ok {
		// Message text must match classic for test.sh testaddrs():
		// grep "E unknown device/address"
		return nil, fmt.Errorf("unknown device/address \"%s\"", s.Type)
	}
	var o *Opened
	err := WithChdir(s, func() error {
		var e error
		o, e = fn(ctx, s, mode, g)
		return e
	})
	return o, err
}

// Opener opens one address type.
type Opener func(context.Context, parse.Spec, Mode, *Global) (*Opened, error)

var (
	openerMu sync.RWMutex
	openers  = map[string]Opener{}
)

// Register associates a classic address type name with an opener.
func Register(name string, fn Opener) {
	openerMu.Lock()
	defer openerMu.Unlock()
	openers[strings.ToUpper(name)] = fn
}

func lookupOpener(typ string) (Opener, bool) {
	openerMu.RLock()
	defer openerMu.RUnlock()
	fn, ok := openers[typ]
	return fn, ok
}

func normalizeType(t string) string {
	t = strings.ToUpper(t)
	// synonyms already uppercased
	return t
}
