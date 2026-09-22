package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func channelModes(opts Options) (lMode, rMode Mode) {
	lMode, rMode = ModeRDWR, ModeRDWR
	if opts.LeftToRight && !opts.RightToLeft {
		return ModeRead, ModeWrite
	}
	if opts.RightToLeft && !opts.LeftToRight {
		return ModeWrite, ModeRead
	}
	return lMode, rMode
}

func Run(ctx context.Context, left, right parse.Channel, g *Global) error {
	preparedLeft, err := PrepareChannel(left)
	if err != nil {
		return err
	}
	preparedRight, err := PrepareChannel(right)
	if err != nil {
		return err
	}
	return RunPrepared(ctx, preparedLeft, preparedRight, g)
}

// RunPrepared opens and relays two prepared channels. It retains immutable
// configuration across accept and fork retry paths.
func RunPrepared(ctx context.Context, left, right PreparedChannel, g *Global) error {
	if err := rejectNoForkOnFirstAddress(left); err != nil {
		return err
	}
	lMode, _ := channelModes(g.Options())

	// Open left first.
	lo, err := OpenPreparedChannel(ctx, left, lMode, g)
	if err != nil {
		// Preserve "unknown device/address" text.
		return err
	}
	return RunOpenedPrepared(ctx, lo, right, g)
}

// RunOpened continues Run after the left address is already open. It closes lo.
func RunOpened(ctx context.Context, lo *Opened, right parse.Channel, g *Global) error {
	prepared, err := PrepareChannel(right)
	if err != nil {
		if lo != nil {
			_ = lo.Close()
		}
		return err
	}
	return RunOpenedPrepared(ctx, lo, prepared, g)
}

// RunOpenedPrepared continues a run with a prepared right channel.
func RunOpenedPrepared(ctx context.Context, lo *Opened, right PreparedChannel, g *Global) error {
	if lo == nil {
		return fmt.Errorf("xio: nil left")
	}
	if lo.nofork() != nil {
		_ = lo.Close()
		return errNoForkOnFirstAddress
	}
	_, rMode := channelModes(g.Options())
	defer func() { _ = lo.Close() }()

	switch lo.payload.(type) {
	case *acceptParent:
		return runForkListen(ctx, lo, right, rMode, g)
	case *repeatedDial:
		return runConnectFork(ctx, lo, right, rMode, g)
	}

	ro, err := OpenPreparedChannel(ctx, right, rMode, g)
	if err != nil {
		return err
	}
	defer func() { _ = ro.Close() }()
	return runOpenedPair(ctx, lo, ro, g, rMode)
}

var errNoForkOnFirstAddress = errors.New("option nofork is not allowed here")

func rejectNoForkOnFirstAddress(left PreparedChannel) error {
	if preparedNoFork(left) {
		return errNoForkOnFirstAddress
	}
	return nil
}

func preparedNoFork(ch PreparedChannel) bool {
	if ch.Single != nil && ch.Single.Config.Common.NoFork.Value {
		return true
	}
	if ch.Dual == nil {
		return false
	}
	return ch.Dual.Left.Config.Common.NoFork.Value || ch.Dual.Right.Config.Common.NoFork.Value
}

// runOpenedPair continues after both endpoints are open. Left accept/dial
// parents never reach here; they keep the right channel closed until each child.
func runOpenedPair(ctx context.Context, lo, ro *Opened, g *Global, rMode Mode) error {
	switch ro.payload.(type) {
	case *acceptParent:
		return runForkListenRight(ctx, lo, ro, g)
	case *repeatedDial:
		return runConnectForkWithLeft(ctx, lo, ro, g)
	}
	if p := ro.nofork(); p != nil {
		// Right EXEC,nofork on left stream (TCP-LISTEN + EXEC,nofork).
		return runExecNoFork(ctx, lo.EffectiveStream(), p.config, g, rMode)
	}
	return transferPair(ctx, lo, ro, g)
}

// streamFromDial applies optional WrapDial, else plain NetStream.
func streamFromDial(o *Opened, c net.Conn) (relay.Stream, error) {
	if o != nil {
		if wrap := o.WrapDial(); wrap != nil {
			return wrap(c)
		}
	}
	return relay.NetStream{Conn: c}, nil
}

// runConnectFork is the CONNECT,fork parent loop: dial, spawn child
// transfer, sleep interval, honour max-children, repeat until ctx cancel.
func runConnectFork(ctx context.Context, lo *Opened, right PreparedChannel, rMode Mode, g *Global) error {
	return runConnectForkLoop(ctx, lo, g, func(cctx context.Context, cg *Global, c net.Conn) {
		left, err := streamFromDial(lo, c)
		if err != nil {
			logForkErr(cg, err)
			return
		}
		ro, err := OpenPreparedChannel(cctx, right, rMode, cg)
		if err != nil {
			logForkErr(cg, err)
			return
		}
		defer func() { _ = ro.Close() }()
		runForkSession(forkSession{
			ctx: cctx, g: cg, conn: left, other: ro,
			connIsLeft: true, mode: rMode, parent: lo,
		})
	})
}

func waitForkChild(ctx context.Context, maxChildren int, opened *Opened) {
	if maxChildren <= 0 || opened == nil || opened.childDone() == nil {
		return
	}
	select {
	case <-opened.childDone():
	case <-ctx.Done():
	}
}

// runConnectForkWithLeft handles CONNECT,fork on the right address with left
// already open (shared stream; sessions serialized).
func runConnectForkWithLeft(ctx context.Context, lo, ro *Opened, g *Global) error {
	// Serialize sessions on the shared left stream. sessionWrap.Close pokes a
	// short deadline and returns immediately; the next wrap, started only after
	// Transfer returns, clears that leftover.
	var leftMu sync.Mutex
	return runConnectForkLoop(ctx, ro, g, func(cctx context.Context, cg *Global, c net.Conn) {
		right, err := streamFromDial(ro, c)
		if err != nil {
			logForkErr(cg, err)
			return
		}
		leftMu.Lock()
		defer leftMu.Unlock()
		runForkSession(forkSession{
			ctx: cctx, g: cg, conn: right, other: lo,
			connIsLeft: false, noCloseLeft: true,
		})
	})
}

// childSlots bounds concurrent fork sessions (nil = unlimited when
// max-children is unset).
type childSlots chan struct{}

func newChildSlots(maxChildren int) childSlots {
	if maxChildren <= 0 {
		return nil
	}
	return make(chan struct{}, maxChildren)
}

// acquire reserves a slot, returning false when ctx completes first.
func (s childSlots) acquire(ctx context.Context) bool {
	if s == nil {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case s <- struct{}{}:
		return true
	}
}

// release frees a reserved slot.
func (s childSlots) release() {
	if s != nil {
		<-s
	}
}

// forEachAccepted runs body in a new goroutine per accepted connection under
// max-children accounting and the peer filter. It waits for active sessions
// before returning. g.Log must be non-nil (the CLI always installs a logger).
func (o *Opened) forEachAccepted(ctx context.Context, ln net.Listener, g *Global, logAccept bool, body func(c net.Conn, cg *Global)) error {
	slots := newChildSlots(o.MaxChildren())
	var children sync.WaitGroup
	defer children.Wait()
	for {
		if !slots.acquire(ctx) {
			return nil
		}
		conn, err := AcceptWithTimeout(ctx, ln, o.AcceptTimeout())
		if err != nil {
			slots.release()
			if errors.Is(err, ErrAcceptTimeout) {
				// Close the parent listener, then wait for accepted
				// sessions to finish. Children are goroutines in the same
				// process, so returning immediately would kill active sessions.
				return ErrAcceptTimeout
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if filter := o.PeerFilter(); filter != nil {
			if ferr := filter(conn); ferr != nil {
				CloseRefusedPeer(conn)
				slots.release()
				if ctx.Err() != nil {
					return nil
				}
				g.Log.Noticef("%s", ferr)
				continue
			}
		}
		if logAccept {
			g.Log.Infof("accepted %s", conn.RemoteAddr())
		}
		time.Sleep(g.Options().ForkWait)
		spawnForkChild(ctx, conn, o, g, slots, &children, body)
	}
}

func forkChildGlobal(c net.Conn, parent *Opened, g *Global) *Global {
	var cg *Global
	if child, ok := c.(interface{ Session() *Global }); ok {
		cg = child.Session()
	}
	if cg == nil {
		cg = g.ForkSession()
	}
	if parent != nil && parent.ChildrenShutup() > 0 && cg != nil && cg.Log != nil {
		cg.Log = cg.Log.WithShutup(parent.ChildrenShutup())
	}
	return cg
}

func spawnForkChild(ctx context.Context, c net.Conn, parent *Opened, g *Global, slots childSlots, children *sync.WaitGroup, run func(net.Conn, *Global)) {
	children.Add(1)
	go func() {
		defer func() { _ = c.Close() }()
		defer slots.release()
		defer children.Done()
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		cg := forkChildGlobal(c, parent, g)
		run(c, cg)
		if cg != nil && cg.Log != nil {
			cg.Log.CloseOwnedSyslog()
		}
	}()
}

func runConnectForkLoop(ctx context.Context, o *Opened, g *Global, child func(context.Context, *Global, net.Conn)) error {
	dial := o.Dial()
	interval := o.Interval()
	if interval <= 0 {
		interval = time.Second
	}
	slots := newChildSlots(o.MaxChildren())
	var children sync.WaitGroup
	defer children.Wait()
	if g != nil && g.Log != nil {
		g.Log.Noticef("starting connect loop (%s)", o.Label)
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		// Wait for a free child slot before dial (parent blocks when
		// at max-children, then connects again).
		if !slots.acquire(ctx) {
			return nil
		}
		conn, err := dial(ctx)
		if err != nil {
			slots.release()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if g != nil && g.Log != nil {
			g.Log.Infof("successfully connected from %s to %s", conn.LocalAddr(), conn.RemoteAddr())
		}
		time.Sleep(g.Options().ForkWait)
		spawnForkChild(ctx, conn, o, g, slots, &children, func(c net.Conn, cg *Global) {
			RememberAddrs(cg, c)
			if err := RememberTLSPeer(cg, c, o.HandshakeTimeout()); err != nil {
				if cg != nil && cg.Log != nil {
					cg.Log.Debugf("connect handshake: %s", err)
				}
				return
			}
			child(ctx, cg, c)
		})
		// Sleep interval before the next connect attempt.
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// forkSession is one accepted or dialed connection paired with the other
// address. other may be deferredNoFork.
type forkSession struct {
	ctx         context.Context
	g           *Global
	conn        relay.Stream
	other       *Opened
	connIsLeft  bool
	mode        Mode
	parent      *Opened
	noCloseLeft bool
}

func (s forkSession) streams() (left, right relay.Stream) {
	if s.connIsLeft {
		return s.conn, s.other.EffectiveStream()
	}
	return s.other.EffectiveStream(), s.conn
}

// runForkSession relays one fork child. Open, nofork start, and transfer
// failures are logged at Error, matching a non-fork run.
func runForkSession(s forkSession) {
	if p := s.other.nofork(); p != nil {
		runForkNoFork(s, p)
		return
	}
	left, right := s.streams()
	if s.g != nil {
		s.g.beginLogicalSession(left, right)
	}
	if s.connIsLeft && s.parent != nil && s.parent.ForkSocketpair() && !relay.ConfigureStreamPair(left, right) {
		rightOpened := s.other
		runForkBridge(s.ctx, left, s.g, nil, func(sp1 *os.File) {
			defer func() { _ = rightOpened.Close() }()
			_ = transferStreams(s.ctx, FileStream(sp1), rightOpened.EffectiveStream(), s.g)
			waitForkChild(s.ctx, s.parent.MaxChildren(), rightOpened)
		})
		return
	}
	var err error
	if s.noCloseLeft {
		err = transferStreamsOpts(s.ctx, left, right, s.g, true, false)
	} else {
		err = transferStreams(s.ctx, left, right, s.g)
		if s.parent != nil {
			waitForkChild(s.ctx, s.parent.MaxChildren(), s.other)
		}
	}
	logForkErr(s.g, err)
}

func runForkNoFork(s forkSession, p *deferredNoFork) {
	if s.parent != nil && s.parent.ForkSocketpair() {
		runForkBridge(s.ctx, s.conn, s.g, func(sp0 *os.File) {
			if s.g != nil {
				s.g.beginLogicalSession(s.conn, FileStream(sp0))
			}
		}, func(sp1 *os.File) {
			logForkErr(s.g, runExecNoFork(s.ctx, FileStream(sp1), p.config, s.g, s.mode))
		})
		return
	}
	logForkErr(s.g, runExecNoFork(s.ctx, s.conn, p.config, s.g, s.mode))
}

// runForkBridge copies left to one end of a socketpair. right owns the other
// end: a nofork command inherits it, or a stream transfer uses it.
func runForkBridge(ctx context.Context, left relay.Stream, g *Global, prep func(*os.File), right func(*os.File)) {
	sp0, sp1, err := unixSocketpairLogged(g)
	if err != nil {
		if g != nil {
			g.Log.Errorf("socketpair: %s", err)
		}
		return
	}
	if prep != nil {
		prep(sp0)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = sp1.Close() }()
		right(sp1)
	}()
	defer func() { _ = sp0.Close() }()
	if err := transferStreams(ctx, left, FileStream(sp0), g); err != nil {
		logForkErr(g, err)
	}
	<-done
}

func logForkErr(g *Global, err error) {
	if err == nil || g == nil {
		return
	}
	g.Log.Errorf("%s", err)
}

func runForkListen(ctx context.Context, lo *Opened, right PreparedChannel, rMode Mode, g *Global) error {
	ln := lo.Listener()
	lg := g.Log
	lg.Noticef("listening on %s", ln.Addr())
	stop := context.AfterFunc(ctx, func() {
		logx.CloseQuiet(ln)
	})
	defer stop()
	return lo.forEachAccepted(ctx, ln, g, true, func(c net.Conn, cg *Global) {
		if err := rememberAccepted(cg, c, lo.afterAccept()); err != nil {
			cg.Log.Errorf("accept: %s", err)
			return
		}
		leftStream, err := streamFromDial(lo, c)
		if err != nil {
			cg.Log.Errorf("wrap accept: %s", err)
			return
		}
		ro, err := OpenPreparedChannel(ctx, right, rMode, cg)
		if err != nil {
			// No "right address:" prefix on the open error.
			logForkErr(cg, err)
			return
		}
		defer func() { _ = ro.Close() }()
		// RECVFROM,fork creates a socketpair per child. Stream listens
		// (TCP-LISTEN,fork PIPE) transfer directly — a bridge would open
		// -r/-R sniff files twice per session.
		// Adapters need the original peer's message boundaries.
		runForkSession(forkSession{
			ctx: ctx, g: cg, conn: leftStream, other: ro,
			connIsLeft: true, mode: rMode, parent: lo,
		})
	})
}

func runForkListenRight(ctx context.Context, lo, ro *Opened, g *Global) error {
	ln := ro.Listener()
	// Shared left (e.g. FILE,o-append) must stay open across all fork children.
	// max-children applies to the listen address (right side here).
	// Shared left stream (FILE append, EXEC socketpair with end-close) cannot
	// safely run concurrent bidirectional transfers on one FD pair — serialize
	// accept sessions. sessionWrap.Close pokes a short deadline and returns
	// immediately; the next wrap, started only after Transfer returns, clears
	// that leftover. end-close still uses socketpair (not pipes).
	var leftMu sync.Mutex
	stop := context.AfterFunc(ctx, func() {
		logx.CloseQuiet(ln)
	})
	defer stop()
	return ro.forEachAccepted(ctx, ln, g, false, func(c net.Conn, cg *Global) {
		leftMu.Lock()
		defer leftMu.Unlock()
		if err := rememberAccepted(cg, c, ro.afterAccept()); err != nil {
			cg.Log.Errorf("accept: %s", err)
			return
		}
		rightStream, err := streamFromDial(ro, c)
		if err != nil {
			cg.Log.Errorf("wrap accept: %s", err)
			return
		}
		// noCloseLeft: do not close/shutdown shared left between children.
		runForkSession(forkSession{
			ctx: ctx, g: cg, conn: rightStream, other: lo,
			connIsLeft: false, noCloseLeft: true,
		})
	})
}

func transferPair(ctx context.Context, lo, ro *Opened, g *Global) error {
	g.beginLogicalSession(lo.EffectiveStream(), ro.EffectiveStream())
	return transferStreams(ctx, lo.EffectiveStream(), ro.EffectiveStream(), g)
}

func transferStreams(ctx context.Context, left, right relay.Stream, g *Global) error {
	return transferStreamsOpts(ctx, left, right, g, StreamIsEndClose(left), StreamIsEndClose(right))
}

func transferStreamsOpts(ctx context.Context, left, right relay.Stream, g *Global, noCloseLeft, noCloseRight bool) error {
	if left == nil || right == nil {
		return fmt.Errorf("nil stream")
	}
	relay.ConfigureStreamPair(left, right)
	time.Sleep(g.Options().TransferWait)
	// Open -r/-R sniff files at transfer start (after peer env is set).
	opts := g.Options()
	if g != nil && (opts.RawLeftPath != "" || opts.RawRightPath != "") {
		if err := openSniffFiles(g); err != nil {
			return err
		}
		defer g.Sniff.closeFiles()
	}
	cfg := relaySessionConfig(opts, noCloseLeft, noCloseRight)
	// Assign only concrete dump files. Converting a nil *os.File directly to
	// io.Writer produces a non-nil interface that reports spurious write errors.
	if g.Sniff.RawLeft != nil {
		cfg.RawLeft = g.Sniff.RawLeft
	}
	if g.Sniff.RawRight != nil {
		cfg.RawRight = g.Sniff.RawRight
	}
	if g != nil && opts.Statistics && g.Log != nil {
		cfg.OnStats = func(st relay.Stats) {
			PrintStats(g.Log, st, cfg.LeftToRight, cfg.RightToLeft, true)
			g.markStatsPrinted()
		}
	}
	// Notice once per side: "socket N (fd M) is at EOF".
	if g != nil && g.Log != nil {
		var eofOnce [3]sync.Once // index 1 and 2
		cfg.OnEOF = func(sock, fd int) {
			if sock < 1 || sock > 2 {
				return
			}
			eofOnce[sock].Do(func() {
				if fd < 0 {
					// Unknown descriptor: do not report fd 0 (stdin).
					g.Log.Noticef("socket %d is at EOF", sock)
					return
				}
				g.Log.Noticef("socket %d (fd %d) is at EOF", sock, fd)
			})
		}
	}
	return relay.Transfer(ctx, left, right, cfg)
}

func relaySessionConfig(opts Options, noCloseLeft, noCloseRight bool) relay.Config {
	leftToRight, rightToLeft := opts.LeftToRight, opts.RightToLeft
	if !leftToRight && !rightToLeft {
		leftToRight, rightToLeft = true, true
	}
	return relay.Config{
		BufferSize:   opts.BlockSize,
		Linger:       opts.Linger,
		IdleTimeout:  opts.Idle,
		LeftToRight:  leftToRight,
		RightToLeft:  rightToLeft,
		Verbose:      opts.Verbose,
		Hex:          opts.Hex,
		Dump:         opts.Dump,
		NoCloseLeft:  noCloseLeft,
		NoCloseRight: noCloseRight,
	}
}

// DefaultCreateMode is open/creat/mkfifo mode (0666 before umask).
const DefaultCreateMode os.FileMode = 0o666

func namedChown(path string, f *os.File, uid, gid int) error {
	if path != "" {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
		return nil
	}
	if f != nil {
		if err := f.Chown(uid, gid); err != nil {
			return fmt.Errorf("fchown: %w", err)
		}
	}
	return nil
}
