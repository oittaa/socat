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

// Options is parsed process configuration. It is immutable after NewSession.
// Sessions share one private *Options; Options() returns a value snapshot.
type Options struct {
	IPVersion    IPVersion
	BlockSize    int
	Linger       time.Duration
	Idle         time.Duration
	LeftToRight  bool
	RightToLeft  bool
	Verbose      bool
	Hex          bool
	Dump         io.Writer
	DumpFDs      bool          // -D: filan-style dump of channel descriptors
	DumpFDOut    io.Writer     // defaults to stderr; independent of -l* destinations
	LogFacility  logx.Facility // syslog facility for -ly/-lm
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

// Global is one logical session. options is a named dependency (not an
// anonymous embed) and is shared with ForkSession results. Remaining
// session-state groups stay embedded until later migrations.
type Global struct {
	options *Options
	sessionPeer
	childResult
	sniffFiles
	sessionRuntime
	// statsPrinted is shared across forks so --statistics prints once.
	// Pointer, never an embedded atomic.Bool, so copies cannot copy a lock.
	statsPrinted *atomic.Bool
	// sessionMu guards SessionVars. Each session CAS-installs its own mutex;
	// createSession must not copy this field.
	sessionMu atomic.Pointer[sync.Mutex]
}

// Options returns a snapshot of this session's process options.
// A nil or uninitialized session yields the zero Options value. The
// snapshot is not shared storage: mutating it cannot change the session
// or its forks.
func (g *Global) Options() Options {
	if g == nil || g.options == nil {
		return Options{}
	}
	return *g.options
}

// sharesOptions reports whether g and other hold the same private Options
// pointer. Tests use this instead of comparing Options() snapshots.
func (g *Global) sharesOptions(other *Global) bool {
	return g != nil && other != nil && g.options != nil && g.options == other.options
}

// NewSession creates a root logical session.
//
// opts is copied onto the heap. Later ForkSession results share that
// *Options. log is stored as-is (forks clone it). Peer maps start empty.
// sessionMu and the child signal table start unset so this session owns them.
func NewSession(opts Options, log *logx.Logger) *Global {
	return createSession(&opts, nil, log, false)
}

// createSession is the single session constructor.
//
// Share: opts (immutable process options).
// Copy: peer maps, child wait status, sniff pointers, and LogMixed when
// from is non-nil. log is cloned from from when log is nil.
// Own: sessionMu (unset) and childSignals (nil).
func createSession(opts *Options, from *Global, log *logx.Logger, forkChild bool) *Global {
	if opts == nil {
		opts = &Options{}
	}
	peer := sessionPeer{}
	var result childResult
	var sniff sniffFiles
	logMixed := false
	var stats *atomic.Bool
	if from != nil {
		peer = sessionPeer{
			SockAddr:    from.SockAddr,
			PeerAddr:    from.PeerAddr,
			SockPort:    from.SockPort,
			PeerPort:    from.PeerPort,
			TLSVars:     cloneStringMap(from.TLSVars),
			SessionVars: from.cloneSessionVars(),
		}
		result = from.childResult
		sniff = from.sniffFiles
		logMixed = from.LogMixed
		stats = from.statsPrinted
		if log == nil && from.Log != nil {
			log = from.Log.Clone()
		}
	}
	if stats == nil && forkChild {
		stats = new(atomic.Bool)
	}
	return &Global{
		options:     opts,
		sessionPeer: peer,
		childResult: result,
		sniffFiles:  sniff,
		sessionRuntime: sessionRuntime{
			ForkChild: forkChild,
			Log:       log,
			LogMixed:  logMixed,
		},
		statsPrinted: stats,
	}
}

// ForkSession returns a per-connection session derived from g.
//
// Share: Options, statsPrinted.
// Copy: peer address strings, child wait status, sniff file pointers, LogMixed.
// Clone: Log, TLSVars, SessionVars (so SOCAT_* env does not race).
// Reset: ForkChild=true, childSignals=nil, sessionMu unset (child installs one).
// Passing *g without a copy is not safe: RememberAddrs writes peer fields.
func (g *Global) ForkSession() *Global {
	if g == nil {
		return createSession(&Options{}, nil, nil, true)
	}
	opts := g.options
	if opts == nil {
		opts = &Options{}
	}
	return createSession(opts, g, nil, true)
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

// OpenedKind names the payload variant. Kind() reports it from the payload.
type OpenedKind int

const (
	// KindReady: transfer I/O is already open.
	KindReady OpenedKind = iota
	// KindListen: bound listener; Run accepts in a fork loop.
	KindListen
	// KindDial: repeated-connect parent; Run dials in a fork loop.
	KindDial
	// KindExec: EXEC/SYSTEM,nofork; Run starts the process after the peer is open.
	KindExec
)

// Opened is a live address endpoint. Construct it with NewReady, NewReadySplit,
// NewAcceptParent, NewRepeatedDial, or NewDeferredNoFork. Variant data lives
// in one private payload; see the ownership table in endpoint_variant.go.
type Opened struct {
	Label string

	payload openedPayload

	// Shared teardown. Order: tty restore (fd still open), payload, Cleanup.
	Cleanup    []func()
	ttyRestore []func()
	closeOnce  sync.Once
	closeErr   error
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
	if o.payload != nil {
		if err := o.payload.close(); err != nil && first == nil {
			first = err
		}
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

// EffectiveStream is the ready-I/O transfer stream. Other variants return nil.
func (o *Opened) EffectiveStream() relay.Stream {
	return o.Stream()
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
	o, err := NewReadySplit(d.Raw, left.EffectiveStream(), right.EffectiveStream())
	if err != nil {
		logx.CloseQuiet(left)
		logx.CloseQuiet(right)
		return nil, err
	}
	o.AddCleanup(func() { logx.CloseQuiet(left) })
	o.AddCleanup(func() { logx.CloseQuiet(right) })
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
// Static option and platform checks already ran in PrepareSpec.
func OpenPreparedSpec(ctx context.Context, prepared PreparedAddress, mode Mode, g *Global) (*Opened, error) {
	if d, ok := registeredAddresses.resolve(prepared.Config.Type); ok {
		warnAddressMode(g, mode, d.Directions)
	}
	var err error
	prepared.Config, err = ResolvePreparedPaths(prepared.Config)
	if err != nil {
		return nil, err
	}
	// lockfile=/waitlock= after chdir= rewrite and before the opener so a
	// failed open still releases.
	release, err := applyAddressLock(ctx, prepared.Config)
	if err != nil {
		return nil, err
	}
	var o *Opened
	err = WithNetNS(prepared.Config.Common.NetNamespace.Value, g, func() error {
		var e error
		o, e = prepared.opener(ctx, prepared.Config, mode, g)
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
		o.SetChildrenShutup(prepared.Config.Common.ChildrenShutup.Value)
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

// Opener opens one address type from prepared settings.
type Opener func(context.Context, addrconfig.Address, Mode, *Global) (*Opened, error)
