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
// The process still exits 0 in this case.
var ErrAcceptTimeout = errors.New("accept timeout")

type acceptResult struct {
	conn net.Conn
	err  error
}

// AcceptWithTimeout accepts one connection and aborts the listener when the
// timeout expires. Closing is intentional: accept-timeout terminates the
// listen address, and it also makes the timeout work for wrapped listeners
// such as TLS and QUIC that do not expose SetDeadline.
func AcceptWithTimeout(ctx context.Context, ln net.Listener, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		return ln.Accept()
	}
	result := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		result <- acceptResult{conn: conn, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case accepted := <-result:
		return accepted.conn, accepted.err
	case <-ctx.Done():
		_ = ln.Close()
		accepted := <-result
		if accepted.conn != nil {
			_ = accepted.conn.Close()
		}
		return nil, ctx.Err()
	case <-timer.C:
		_ = ln.Close()
		accepted := <-result
		if accepted.conn != nil {
			_ = accepted.conn.Close()
		}
		return nil, ErrAcceptTimeout
	}
}

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
	// IPv4Default matches -4. Listen still honours SOCAT_DEFAULT_LISTEN_IP;
	// explicit IPv4 (-4) does not.
	IPv4Default IPVersion = iota
	IPv4
	IPv6
	IPvAny // -0
)

// globalState is the copyable part of Global. The session mutex stays off this
// struct so forkSession can copy under the session lock without racing
// CAS-install of the mutex.
type globalState struct {
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
	DumpFDs      bool      // -D: filan-style dump of channel descriptors
	DumpFDOut    io.Writer // defaults to stderr; independent of -l* destinations
	LogMixed     bool      // -lm: stderr until both endpoints are ready
	LogFacility  string    // syslog facility for -ly/-lm
	Statistics   bool
	statsPrinted *atomic.Bool // pointer so forkSession can copy Global without copying a lock
	// childSignals is this logical session's four-slot signal table.
	// forkSession nils it so LISTEN,fork goroutines do not share one table.
	childSignals *childSignalSession
	Experimental bool // --experimental (netns= warning)
	// ForkChild is set on LISTEN/CONNECT,fork session goroutines. FD,end-close
	// then closes only the per-session duplicate, like a fork child's copy of
	// the inherited descriptor.
	ForkChild bool

	// Peer info from the most recently accepted/connected socket (for SOCAT_* env).
	SockAddr string
	PeerAddr string
	SockPort string
	PeerPort string

	// TLSVars contains TLS session metadata without the TLS_/OPENSSL_ prefix.
	// Children receive both the preferred *_TLS_* names and *_OPENSSL_*
	// compatibility aliases.
	TLSVars map[string]string

	// SessionVars contains other per-session output variables without the
	// executable prefix (for example TIMESTAMP or POSIXMQ_PRIO).
	SessionVars map[string]string

	// Child process exit (EXEC/SYSTEM): non-zero promotes socat process exit.
	ChildExitCode int
	ChildErr      error

	// -r / -R raw transfer dumps (left→right / right→left).
	// Path templates may contain $PROGNAME, $TIMESTAMP, $MICROS, $$, $ENV.
	// Files are opened at transfer start (after peer is known) with CLOEXEC.
	RawLeftPath  string
	RawRightPath string
	Progname     string // -lp value; default "socat"
	RawLeft      *os.File
	RawRight     *os.File
}

// Global holds process-wide options affecting address open.
type Global struct {
	globalState
	// sessionMu guards SessionVars. Kept off globalState so a struct copy
	// cannot race CAS-install. Each session installs its own lock.
	sessionMu atomic.Pointer[sync.Mutex]
}

// forkSession returns a per-connection copy of g.
// Peer/TLS fields must be unique per fork child so SOCAT_* env does not race.
// statsPrinted is a shared pointer so --statistics still prints once.
// Passing *g without a copy is not safe: RememberAddrs writes those fields.
func (g *Global) forkSession() *Global {
	if g == nil {
		return &Global{statsPrinted: new(atomic.Bool), ForkChild: true}
	}
	unlock := g.lockSession()
	vars := cloneStringMap(g.SessionVars)
	cg := Global{globalState: g.globalState}
	unlock()
	cg.ForkChild = true
	if g.Log != nil {
		cg.Log = g.Log.Clone()
	}
	cg.TLSVars = cloneStringMap(g.TLSVars)
	cg.SessionVars = vars
	cg.childSignals = nil
	if cg.statsPrinted == nil {
		cg.statsPrinted = new(atomic.Bool)
	}
	return &cg
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (g *Global) statsAlreadyPrinted() bool {
	return g != nil && g.statsPrinted != nil && g.statsPrinted.Load()
}

func (g *Global) markStatsPrinted() {
	if g == nil {
		return
	}
	g.ensureStatsFlag()
	g.statsPrinted.Store(true)
}

// EnsureStatsFlag allocates the shared --statistics once-flag on the parent.
func (g *Global) EnsureStatsFlag() {
	if g != nil {
		g.ensureStatsFlag()
	}
}

func (g *Global) ensureStatsFlag() {
	if g.statsPrinted == nil {
		g.statsPrinted = new(atomic.Bool)
	}
}

// OpenedKind says how Run uses an Opened. One Opened, not a wrapper hierarchy:
// Kind selects which embedded group is live.
type OpenedKind int

const (
	// KindReady: transfer I/O is already open (readyIO).
	KindReady OpenedKind = iota
	// KindListen: bound listener; Run accepts in a fork loop (listenLoop).
	KindListen
	// KindDial: repeated-connect parent; Run dials in a fork loop (dialLoop).
	KindDial
	// KindExec: EXEC/SYSTEM,nofork; Run starts the process after the peer is open.
	KindExec
)

// ListenKind is KindListen when fork is set, else KindReady.
func ListenKind(fork bool) OpenedKind {
	if fork {
		return KindListen
	}
	return KindReady
}

// readyIO is payload I/O for KindReady, including dual read/write halves.
// Listen/dial parents leave these nil until a child wraps a conn.
type readyIO struct {
	Stream relay.Stream
	Read   relay.Stream
	Write  relay.Stream
}

// listenLoop is the KindListen parent: bound socket and accept-loop knobs.
// Listener is nil after a non-fork accept hands the conn to readyIO.
type listenLoop struct {
	Listener       net.Listener
	ForkSocketpair bool // datagram sessions bridged through a socketpair
	PeerFilter     func(net.Conn) error
	AcceptTimeout  time.Duration
}

// dialLoop is the KindDial parent: repeated connect until cancel.
type dialLoop struct {
	// Dial completes the full open, including TLS/SOCKS/HTTP handshake.
	Dial     func(ctx context.Context) (net.Conn, error)
	Interval time.Duration
}

// forkLoop is shared by listen and dial parents.
type forkLoop struct {
	MaxChildren    int
	ChildrenShutup int // demote child diagnostics; parent/siblings unchanged
	// WrapDial wraps each accepted or dialed conn (crlf, escape, ...). Optional.
	WrapDial         func(net.Conn) (relay.Stream, error)
	HandshakeTimeout time.Duration
}

// endpointClose is exactly-once teardown. Order: tty restore (fd still open),
// ready stream, listener, then Cleanup hooks.
type endpointClose struct {
	Cleanup    []func()
	ttyRestore []func()
	closeOnce  sync.Once
	closeErr   error
}

// Opened is a live address endpoint. Kind selects the mode; callers still use
// the promoted field names (o.Stream, o.Listener, o.Dial, ...).
type Opened struct {
	Kind  OpenedKind
	Label string
	readyIO
	listenLoop
	dialLoop
	forkLoop
	endpointClose
	// NoForkSpec is KindExec: EXEC/SYSTEM,nofork started in Run with the peer FD as stdio.
	NoForkSpec *parse.Spec
	// childDone closes when an EXEC/SYSTEM/SHELL child exits. Fork loops with
	// max-children retain their slot until that process, not just its relay,
	// has finished.
	childDone <-chan struct{}
}

// Close runs endpoint teardown once. Later calls return the first result.
func (o *Opened) Close() error {
	o.closeOnce.Do(func() {
		o.closeErr = o.close()
	})
	return o.closeErr
}

func (o *Opened) close() error {
	var first error
	o.restoreTTY()
	if err := o.closeReady(); err != nil && first == nil {
		first = err
	}
	if err := o.closeListen(); err != nil && first == nil {
		first = err
	}
	o.runCleanup()
	return first
}

// restoreTTY runs termios restore while the stream fd is still open.
func (o *Opened) restoreTTY() {
	for i := len(o.ttyRestore) - 1; i >= 0; i-- {
		o.ttyRestore[i]()
	}
}

func (o *Opened) closeReady() error {
	if o.Stream == nil {
		return nil
	}
	return o.Stream.Close()
}

func (o *Opened) closeListen() error {
	if o.Listener == nil {
		return nil
	}
	err := o.Listener.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (o *Opened) runCleanup() {
	for i := len(o.Cleanup) - 1; i >= 0; i-- {
		o.Cleanup[i]()
	}
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
		logx.CloseQuiet(left)
		return nil, fmt.Errorf("dual write side: %w", err)
	}
	o := &Opened{
		Read:  left.EffectiveStream(),
		Write: right.EffectiveStream(),
		Label: d.Raw,
	}
	o.AddCleanup(func() { logx.CloseQuiet(left) })
	o.AddCleanup(func() { logx.CloseQuiet(right) })
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
	orig := strings.ToUpper(s.Type)
	s.Type = orig
	fn, ok := lookupOpener(s.Type)
	if !ok {
		return nil, fmt.Errorf("unknown device/address \"%s\"", orig)
	}
	// Rewrite to the registered keyword so Type-based opener logic (chdir
	// UNIX paths, ABSTRACT-CLIENT autodetect, family openers) sees the
	// canonical name. Direct registrations such as TCP-L keep their own name.
	if d, ok := registeredAddresses.resolve(s.Type); ok {
		s.Type = d.Name
		warnAddressMode(g, mode, d.Directions)
	}
	var err error
	s, err = ResolveChdirPaths(s)
	if err != nil {
		return nil, err
	}
	if err := RejectUnsupportedIPAncillary(s); err != nil {
		return nil, err
	}
	if err := RejectUnsupportedTermios(s); err != nil {
		return nil, err
	}
	if err := RejectUnsupportedRecvErr(s); err != nil {
		return nil, err
	}
	if err := RejectUnsupportedRemainingIPv4(s); err != nil {
		return nil, err
	}
	if err := RejectUnsupportedListenBacklog(s); err != nil {
		return nil, err
	}
	// lockfile=/waitlock= after chdir= rewrite and before the opener so a
	// failed open still releases.
	release, err := applyAddressLock(ctx, s)
	if err != nil {
		return nil, err
	}
	var o *Opened
	err = WithNetNS(s, g, func() error {
		var e error
		o, e = fn(ctx, s, mode, g)
		return e
	})
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	if o == nil {
		if release != nil {
			release()
		}
		return nil, nil
	}
	if release != nil {
		o.AddCleanup(release)
	}
	if value, ok := optionValueAny(s, "children-shutup", "child-shutup"); ok {
		n, parseErr := ParseIntAny(value)
		if parseErr != nil || n < 0 {
			_ = o.Close()
			return nil, fmt.Errorf("children-shutup: invalid value %q", value)
		}
		o.ChildrenShutup = n
	}
	return o, nil
}

func warnAddressMode(g *Global, opened, supported Mode) {
	if g == nil || g.Log == nil {
		return
	}
	openBits, supBits := modeAccBits(opened), modeAccBits(supported)
	if openBits&^supBits == 0 {
		return
	}
	g.Log.Warningf("address is opened in %s mode but only supports %s", modeAccText(opened), modeAccText(supported))
}

func modeAccBits(m Mode) int {
	switch m {
	case ModeRead:
		return 1
	case ModeWrite:
		return 2
	default:
		return 3
	}
}

func modeAccText(m Mode) string {
	switch m {
	case ModeRead:
		return "read-only"
	case ModeWrite:
		return "write-only"
	default:
		return "read-write"
	}
}

// Opener opens one address type.
type Opener func(context.Context, parse.Spec, Mode, *Global) (*Opened, error)
