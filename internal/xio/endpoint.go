package xio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
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

// AcceptWithTimeout accepts one connection and closes the listener when the
// timeout expires or ctx is done. Closing is intentional: accept-timeout
// terminates the listen address, and it also makes the wait work for wrapped
// listeners such as TLS and QUIC that do not expose SetDeadline.
func AcceptWithTimeout(ctx context.Context, ln net.Listener, timeout time.Duration) (net.Conn, error) {
	return acceptUntil(ctx, ln, timeout, func() { _ = ln.Close() })
}

// acceptUntil waits for ln.Accept. timeout>0 starts a timer; a non-nil
// ctx.Done is always watched. abort unblocks Accept (typically Close).
func acceptUntil(ctx context.Context, ln net.Listener, timeout time.Duration, abort func()) (net.Conn, error) {
	if timeout <= 0 && (ctx == nil || ctx.Done() == nil) {
		return ln.Accept()
	}
	result := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		result <- acceptResult{conn: conn, err: err}
	}()
	var timerC <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		timerC = timer.C
	}
	var ctxDone <-chan struct{}
	if ctx != nil {
		ctxDone = ctx.Done()
	}
	select {
	case accepted := <-result:
		return accepted.conn, accepted.err
	case <-ctxDone:
		if abort != nil {
			abort()
		}
		return drainAccept(result, ctx.Err())
	case <-timerC:
		if abort != nil {
			abort()
		}
		return drainAccept(result, ErrAcceptTimeout)
	}
}

func drainAccept(result <-chan acceptResult, err error) (net.Conn, error) {
	accepted := <-result
	if accepted.conn != nil {
		_ = accepted.conn.Close()
	}
	return nil, err
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

// globalOptions is parsed process configuration. It is immutable after
// buildGlobal. ForkSession copies it by value.
type globalOptions struct {
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
	LogFacility  string    // syslog facility for -ly/-lm
	Statistics   bool
	Experimental bool // --experimental (netns= warning)
	// -r / -R path templates. Files live on sniffFiles, opened after peer is known.
	RawLeftPath  string
	RawRightPath string
	Progname     string // -lp value; default "socat"
}

// sessionPeer is per-connection identity for SOCAT_* env and sniff paths.
// ForkSession clones the maps; RememberAddrs overwrites the address strings.
type sessionPeer struct {
	SockAddr string
	PeerAddr string
	SockPort string
	PeerPort string
	// TLSVars holds TLS metadata without the TLS_/OPENSSL_ prefix.
	// Children get both *_TLS_* names and *_OPENSSL_* aliases.
	TLSVars map[string]string
	// SessionVars holds other per-session output names without the executable
	// prefix (for example TIMESTAMP or POSIXMQ_PRIO).
	SessionVars map[string]string
}

// childResult is the last EXEC/SYSTEM wait status on this session.
// Copied into the fork child (listen parents are typically zero).
type childResult struct {
	ChildExitCode int
	ChildErr      error
}

// sniffFiles are -r/-R dumps. ForkSession copies the pointers; openSniffFiles
// then closes and reopens so parent and child do not share an *os.File.
type sniffFiles struct {
	RawLeft  *os.File
	RawRight *os.File
}

// sessionRuntime is per-logical-session state that is not parsed options.
// ForkSession sets ForkChild, clones Log, copies LogMixed, and starts with a
// nil signal table.
type sessionRuntime struct {
	// ForkChild is set on LISTEN/CONNECT,fork session goroutines. FD,end-close
	// then closes only the per-session duplicate, like a fork child's copy of
	// the inherited descriptor.
	ForkChild bool
	// childSignals is this logical session's four-slot signal table.
	childSignals *childSignalSession
	Log          *logx.Logger
	LogMixed     bool // -lm: stderr until both endpoints are ready
}

// Global is parsed options plus the current logical session's runtime state.
// Callers still use the promoted field names (g.BlockSize, g.SockAddr, ...).
type Global struct {
	globalOptions
	sessionPeer
	childResult
	sniffFiles
	sessionRuntime
	// statsPrinted is shared across forks so --statistics prints once.
	// Pointer, never an embedded atomic.Bool, so copies cannot copy a lock.
	statsPrinted *atomic.Bool
	// sessionMu guards SessionVars. Each session CAS-installs its own mutex;
	// ForkSession must not copy this field.
	sessionMu atomic.Pointer[sync.Mutex]
}

// ForkSession returns a per-connection session derived from g.
//
// Copy: options, peer address strings, child wait status, sniff file pointers, LogMixed.
// Clone: Log, TLSVars, SessionVars (so SOCAT_* env does not race).
// Share: statsPrinted.
// Reset: ForkChild=true, childSignals=nil, sessionMu unset (child installs one).
// Passing *g without a copy is not safe: RememberAddrs writes peer fields.
func (g *Global) ForkSession() *Global {
	if g == nil {
		return &Global{sessionRuntime: sessionRuntime{ForkChild: true}, statsPrinted: new(atomic.Bool)}
	}
	unlock := g.lockSession()
	vars := cloneStringMap(g.SessionVars)
	unlock()
	var log *logx.Logger
	if g.Log != nil {
		log = g.Log.Clone()
	}
	stats := g.statsPrinted
	if stats == nil {
		stats = new(atomic.Bool)
	}
	return &Global{
		globalOptions: g.globalOptions,
		sessionPeer: sessionPeer{
			SockAddr:    g.SockAddr,
			PeerAddr:    g.PeerAddr,
			SockPort:    g.SockPort,
			PeerPort:    g.PeerPort,
			TLSVars:     cloneStringMap(g.TLSVars),
			SessionVars: vars,
		},
		childResult: g.childResult,
		sniffFiles:  g.sniffFiles,
		sessionRuntime: sessionRuntime{
			ForkChild: true,
			Log:       log,
			LogMixed:  g.LogMixed,
		},
		statsPrinted: stats,
	}
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

// OpenedKind says how Run uses an Opened. Kind selects which fields are live.
type OpenedKind int

const (
	// KindReady: transfer I/O is already open (Stream / Read / Write).
	KindReady OpenedKind = iota
	// KindListen: bound listener; Run accepts in a fork loop.
	KindListen
	// KindDial: repeated-connect parent; Run dials in a fork loop.
	KindDial
	// KindExec: EXEC/SYSTEM,nofork; Run starts the process after the peer is open.
	KindExec
)

// Opened is a live address endpoint. Kind selects the mode; callers still use
// the field names (o.Stream, o.Listener, o.Dial, ...).
type Opened struct {
	Kind  OpenedKind
	Label string

	// Ready I/O. Listen/dial parents leave these nil until a child wraps a conn.
	Stream relay.Stream
	Read   relay.Stream
	Write  relay.Stream

	// KindListen: bound socket and accept-loop knobs.
	Listener       net.Listener
	ForkSocketpair bool // datagram sessions bridged through a socketpair
	PeerFilter     func(net.Conn) error
	AcceptTimeout  time.Duration

	// KindDial: repeated connect until cancel. Dial includes TLS/SOCKS/HTTP handshake.
	Dial     func(ctx context.Context) (net.Conn, error)
	Interval time.Duration

	// Listen and dial parents.
	MaxChildren    int
	ChildrenShutup int // demote child diagnostics; parent/siblings unchanged
	// WrapDial wraps each accepted or dialed conn (crlf, escape, ...). Optional.
	WrapDial         func(net.Conn) (relay.Stream, error)
	HandshakeTimeout time.Duration

	// Exactly-once teardown. Order: tty restore (fd still open), Stream, Listener, Cleanup.
	Cleanup    []func()
	ttyRestore []func()
	closeOnce  sync.Once
	closeErr   error

	// NoForkSpec is KindExec: EXEC/SYSTEM,nofork started in Run with the peer FD as stdio.
	NoForkSpec *parse.Spec
	// NoForkConfig is the immutable EXEC/SYSTEM/SHELL configuration retained
	// until Run attaches the peer descriptor.
	NoForkConfig *addrconfig.Address
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

// OpenChannel prepares and opens a parsed address channel.
func OpenChannel(ctx context.Context, ch parse.Channel, mode Mode, g *Global) (*Opened, error) {
	prepared, err := PrepareChannel(ch)
	if err != nil {
		return nil, err
	}
	return OpenPreparedChannel(ctx, prepared, mode, g)
}

// OpenPreparedChannel opens a previously prepared channel without repeating
// registry resolution or common static decoding.
func OpenPreparedChannel(ctx context.Context, ch PreparedChannel, mode Mode, g *Global) (*Opened, error) {
	if ch.IsDual() {
		return openPreparedDual(ctx, ch.Dual, g)
	}
	if ch.Single == nil {
		return nil, fmt.Errorf("xio: empty channel")
	}
	return OpenPreparedSpec(ctx, *ch.Single, mode, g)
}

func openPreparedDual(ctx context.Context, d *PreparedDual, g *Global) (*Opened, error) {
	left, err := OpenPreparedSpec(ctx, d.Left, ModeRead, g)
	if err != nil {
		return nil, fmt.Errorf("dual read side: %w", err)
	}
	right, err := OpenPreparedSpec(ctx, d.Right, ModeWrite, g)
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

// OpenSpec prepares and opens a single address.
func OpenSpec(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	prepared, err := PrepareSpec(s)
	if err != nil {
		return nil, err
	}
	return OpenPreparedSpec(ctx, prepared, mode, g)
}

// OpenPreparedSpec opens a prepared address. Resource acquisition and
// namespace work stay here so preparation never changes their lifetime.
func OpenPreparedSpec(ctx context.Context, prepared PreparedAddress, mode Mode, g *Global) (*Opened, error) {
	ctx = withPreparedConfig(ctx, prepared.Config)
	s := prepared.legacy
	if d, ok := registeredAddresses.resolve(prepared.Config.Type); ok {
		warnAddressMode(g, mode, d.Directions)
	}
	var err error
	// Process-wide setuid/chroot/substuser names are recognized so the
	// error explains the isolation requirement instead of "unknown option".
	if err := RejectUnsupportedIsolation(s); err != nil {
		return nil, err
	}
	s, err = ResolveChdirPaths(s)
	if err != nil {
		return nil, err
	}
	prepared.Config = withResolvedPreparedPaths(prepared.Config, s)
	ctx = withPreparedConfig(ctx, prepared.Config)
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
		o, e = prepared.opener(ctx, s, mode, g)
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
	if prepared.Config.Common.ChildrenShutup.Set {
		o.ChildrenShutup = prepared.Config.Common.ChildrenShutup.Value
	}
	return o, nil
}

func withResolvedPreparedPaths(config addrconfig.Address, spec parse.Spec) addrconfig.Address {
	if config.Process.Chdir.Set {
		if option, ok := spec.OptionNamed("chdir"); ok {
			config.Process.Chdir.Value = option.Value
		}
	}
	if config.Terminal.Link.Set {
		if option, ok := spec.OptionNamed("link"); ok {
			config.Terminal.Link.Value = option.Value
		}
	}
	return config
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
