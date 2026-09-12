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
	// -r / -R path templates. Files live on Sniff, opened after peer is known.
	RawLeftPath  string
	RawRightPath string
	Progname     string // -lp value; default "socat"
}

// Peer is per-connection identity for SOCAT_* env and sniff paths.
// ForkSession copies the strings and clones the maps. RememberAddrs
// overwrites the address strings on this session only.
type Peer struct {
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

// Child is the last EXEC/SYSTEM wait status on this session.
// ForkSession copies the value (listen parents are typically zero).
type Child struct {
	ExitCode int
	Err      error
}

// Sniff is this session's -r/-R dump files. ForkSession does not share the
// parent's *os.File pointers. openSniffFiles closes this session's files
// and opens new ones from Options path templates so the session owns them.
type Sniff struct {
	RawLeft  *os.File
	RawRight *os.File
}

func (s *Sniff) closeFiles() {
	if s == nil {
		return
	}
	if s.RawLeft != nil {
		_ = s.RawLeft.Close()
		s.RawLeft = nil
	}
	if s.RawRight != nil {
		_ = s.RawRight.Close()
		s.RawRight = nil
	}
}

// Global is one logical session. Named dependencies (not anonymous embeds):
// options (shared), Peer (copied), Log (cloned on fork), Sniff (session-owned
// files), Child (copied wait status).
type Global struct {
	options *Options
	Peer    Peer
	Child   Child
	Sniff   Sniff
	// ForkChild is set on LISTEN/CONNECT,fork session goroutines. FD,end-close
	// then closes only the per-session duplicate, like a fork child's copy of
	// the inherited descriptor.
	ForkChild bool
	// childSignals is this logical session's four-slot signal table.
	// NewSession and ForkSession each allocate an empty table.
	childSignals *childSignalSession
	Log          *logx.Logger
	LogMixed     bool // -lm: stderr until both endpoints are ready
	// statsPrinted is shared across forks so --statistics prints once.
	// Pointer, never an embedded atomic.Bool, so copies cannot copy a lock.
	statsPrinted *atomic.Bool
	// sessionMu guards Peer.SessionVars. NewSession and ForkSession each
	// store a mutex. Zero-value sessions still CAS-install one on first use.
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
// Share: later ForkSession results share the heap-copied *Options.
// Copy: none (this is the root).
// Own: sessionMu and an empty childSignals table. log is stored as-is
// (forks clone it). Peer maps start empty. Sniff starts empty.
func NewSession(opts Options, log *logx.Logger) *Global {
	copied := opts
	g := &Global{
		options:      &copied,
		Log:          log,
		statsPrinted: new(atomic.Bool),
	}
	ownSessionSync(g)
	return g
}

func cloneLogger(log *logx.Logger) *logx.Logger {
	if log == nil {
		return nil
	}
	return log.Clone()
}

func copyPeer(from *Global) Peer {
	if from == nil {
		return Peer{}
	}
	// Field-by-field so SessionVars is only read under cloneSessionVars.
	return Peer{
		SockAddr:    from.Peer.SockAddr,
		PeerAddr:    from.Peer.PeerAddr,
		SockPort:    from.Peer.SockPort,
		PeerPort:    from.Peer.PeerPort,
		TLSVars:     cloneStringMap(from.Peer.TLSVars),
		SessionVars: from.cloneSessionVars(),
	}
}

func ownSessionSync(g *Global) {
	if g == nil {
		return
	}
	g.sessionMu.Store(new(sync.Mutex))
	g.childSignals = new(childSignalSession)
}

// ForkSession returns a per-connection session derived from g.
//
// Share: Options, statsPrinted.
// Copy: Peer (maps cloned), Child, LogMixed.
// Clone: Log.
// Own: Sniff (empty), a new sessionMu, and a new empty childSignals table.
// Passing *g without ForkSession is not safe: RememberAddrs writes Peer.
func (g *Global) ForkSession() *Global {
	if g == nil {
		child := &Global{
			options:      &Options{},
			ForkChild:    true,
			statsPrinted: new(atomic.Bool),
		}
		ownSessionSync(child)
		return child
	}
	opts := g.options
	if opts == nil {
		opts = &Options{}
	}
	stats := g.statsPrinted
	if stats == nil {
		stats = new(atomic.Bool)
	}
	child := &Global{
		options:      opts,
		Peer:         copyPeer(g),
		Child:        g.Child,
		ForkChild:    true,
		Log:          cloneLogger(g.Log),
		LogMixed:     g.LogMixed,
		statsPrinted: stats,
	}
	ownSessionSync(child)
	return child
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
