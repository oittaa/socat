package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func channelModes(g *Global) (lMode, rMode Mode) {
	lMode, rMode = ModeRDWR, ModeRDWR
	if g == nil {
		return lMode, rMode
	}
	if g.LeftToRight && !g.RightToLeft {
		return ModeRead, ModeWrite
	}
	if g.RightToLeft && !g.LeftToRight {
		return ModeWrite, ModeRead
	}
	return lMode, rMode
}

func Run(ctx context.Context, left, right parse.Channel, g *Global) error {
	lMode, _ := channelModes(g)

	// Open left first (classic order)
	lo, err := OpenChannel(ctx, left, lMode, g)
	if err != nil {
		// Preserve classic "unknown device/address" text for test.sh testaddrs().
		return err
	}
	return RunOpened(ctx, lo, right, g)
}

// RunOpened continues Run after the left address is already open. It closes lo.
func RunOpened(ctx context.Context, lo *Opened, right parse.Channel, g *Global) error {
	if lo == nil {
		return fmt.Errorf("xio: nil left")
	}
	lMode, rMode := channelModes(g)
	defer func() { _ = lo.Close() }()

	switch lo.Kind {
	case KindListen:
		if lo.Listener == nil {
			return fmt.Errorf("%s: listen fork without listener", lo.Label)
		}
		return runForkListen(ctx, lo, right, rMode, g)
	case KindDial:
		// Client CONNECT/TLS-CONNECT with fork (classic xio-ipapp loop).
		return runConnectFork(ctx, lo, right, rMode, g)
	case KindExec:
		if lo.NoForkSpec == nil {
			return fmt.Errorf("%s: exec nofork without spec", lo.Label)
		}
		// Left EXEC,nofork: open right first, then exec on right's stream.
		ro, err := OpenChannel(ctx, right, rMode, g)
		if err != nil {
			return err
		}
		defer func() { _ = ro.Close() }()
		return runExecNoFork(ctx, ro.EffectiveStream(), *lo.NoForkSpec, g, lMode)
	}

	ro, err := OpenChannel(ctx, right, rMode, g)
	if err != nil {
		return err
	}
	defer func() { _ = ro.Close() }()

	switch ro.Kind {
	case KindExec:
		if ro.NoForkSpec == nil {
			return fmt.Errorf("%s: exec nofork without spec", ro.Label)
		}
		// Right EXEC,nofork on left stream (TCP-LISTEN + EXEC,nofork).
		return runExecNoFork(ctx, lo.EffectiveStream(), *ro.NoForkSpec, g, rMode)
	case KindListen:
		if ro.Listener == nil {
			return fmt.Errorf("%s: listen fork without listener", ro.Label)
		}
		// Listen on right with left already open.
		return runForkListenRight(ctx, lo, ro, g)
	case KindDial:
		return runConnectForkWithLeft(ctx, lo.EffectiveStream(), ro, g)
	}

	return transferPair(ctx, lo, ro, g)
}

// streamFromDial applies optional WrapDial, else plain NetStream.
func streamFromDial(o *Opened, c net.Conn) (relay.Stream, error) {
	if o != nil && o.WrapDial != nil {
		return o.WrapDial(c)
	}
	return relay.NetStream{Conn: c}, nil
}

// runConnectFork is the classic CONNECT,fork parent loop: dial, spawn child
// transfer, sleep interval, honour max-children, repeat until ctx cancel.
func runConnectFork(ctx context.Context, lo *Opened, right parse.Channel, rMode Mode, g *Global) error {
	return runConnectForkLoop(ctx, lo, g, func(cctx context.Context, cg *Global, c net.Conn) error {
		left, err := streamFromDial(lo, c)
		if err != nil {
			return err
		}
		ro, err := OpenChannel(cctx, right, rMode, cg)
		if err != nil {
			return err
		}
		defer func() { _ = ro.Close() }()
		return transferStreams(cctx, left, ro.EffectiveStream(), cg)
	})
}

// runConnectForkWithLeft handles CONNECT,fork on the right address with left
// already open (shared stream; sessions serialized).
func runConnectForkWithLeft(ctx context.Context, left relay.Stream, ro *Opened, g *Global) error {
	// Serialize sessions on the shared left stream. sessionWrap.Close pokes a
	// short deadline and returns immediately; the next wrap, started only after
	// Transfer returns, clears that leftover.
	var leftMu sync.Mutex
	return runConnectForkLoop(ctx, ro, g, func(cctx context.Context, cg *Global, c net.Conn) error {
		right, err := streamFromDial(ro, c)
		if err != nil {
			return err
		}
		leftMu.Lock()
		defer leftMu.Unlock()
		return transferStreamsOpts(cctx, left, right, cg, true, false)
	})
}

// childSlots bounds concurrent fork sessions (nil = unlimited, classic
// default when max-children is unset).
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
// max-children accounting and the peer filter. It returns nil on ctx
// completion and the accept error otherwise. g.Log must be non-nil (the CLI
// always installs a logger).
func (o *Opened) forEachAccepted(ctx context.Context, ln net.Listener, g *Global, logAccept bool, body func(c net.Conn, cg *Global)) error {
	slots := newChildSlots(o.MaxChildren)
	var children sync.WaitGroup
	for {
		if !slots.acquire(ctx) {
			return nil
		}
		conn, err := AcceptWithTimeout(ctx, ln, o.AcceptTimeout)
		if err != nil {
			slots.release()
			if errors.Is(err, ErrAcceptTimeout) {
				// Classic closes the parent listener, then waits for an accepted
				// fork child to finish. Our children are goroutines in the same
				// process, so returning immediately would kill active sessions.
				children.Wait()
				return ErrAcceptTimeout
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if o.PeerFilter != nil {
			if ferr := o.PeerFilter(conn); ferr != nil {
				g.Log.Noticef("%s", ferr)
				CloseRefusedPeer(conn)
				slots.release()
				continue
			}
		}
		if logAccept {
			g.Log.Infof("accepted %s", conn.RemoteAddr())
		}
		WaitFromEnv("SOCAT_FORK_WAIT")
		children.Add(1)
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			defer slots.release()
			defer children.Done()
			cg := g.forkSession()
			if o.ChildrenShutup > 0 && cg.Log != nil {
				cg.Log = cg.Log.WithShutup(o.ChildrenShutup)
			}
			RememberAddrs(cg, c)
			body(c, cg)
		}(conn)
	}
}

func runConnectForkLoop(ctx context.Context, o *Opened, g *Global, child func(context.Context, *Global, net.Conn) error) error {
	if o.Dial == nil {
		return fmt.Errorf("%s: connect fork without dialer", o.Label)
	}
	interval := o.Interval
	if interval <= 0 {
		interval = time.Second
	}
	slots := newChildSlots(o.MaxChildren)
	if g != nil && g.Log != nil {
		g.Log.Noticef("starting connect loop (%s)", o.Label)
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		// Wait for a free child slot before dial (classic: parent blocks when
		// num_child >= max-children, then connects again).
		if !slots.acquire(ctx) {
			return nil
		}
		conn, err := o.Dial(ctx)
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
		WaitFromEnv("SOCAT_FORK_WAIT")
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			defer slots.release()
			cg := g.forkSession()
			if o.ChildrenShutup > 0 && cg.Log != nil {
				cg.Log = cg.Log.WithShutup(o.ChildrenShutup)
			}
			RememberAddrs(cg, c)
			if err := RememberTLSPeer(cg, c, o.HandshakeTimeout); err != nil {
				if cg.Log != nil {
					cg.Log.Debugf("connect handshake: %s", err)
				}
				return
			}
			if err := child(ctx, cg, c); err != nil {
				if cg.Log != nil {
					cg.Log.Debugf("connect child: %s", err)
				}
			}
		}(conn)
		// Classic parent always sleeps interval before the next connect attempt.
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

func runForkListen(ctx context.Context, lo *Opened, right parse.Channel, rMode Mode, g *Global) error {
	ln := lo.Listener
	lg := g.Log
	lg.Noticef("listening on %s", ln.Addr())
	go func() {
		<-ctx.Done()
		logx.CloseQuiet(ln)
	}()
	return lo.forEachAccepted(ctx, ln, g, true, func(c net.Conn, cg *Global) {
		if err := RememberTLSPeer(cg, c, lo.HandshakeTimeout); err != nil {
			cg.Log.Errorf("handshake: %s", err)
			return
		}
		leftStream, err := streamFromDial(lo, c)
		if err != nil {
			cg.Log.Errorf("wrap accept: %s", err)
			return
		}
		ro, err := OpenChannel(ctx, right, rMode, cg)
		if err != nil {
			// Classic greps `E open(` for RECVFROM_FORK_LOOP — no "right address:" prefix.
			cg.Log.Errorf("%s", err)
			return
		}
		// Classic RECVFROM,fork creates a socketpair per child (FD-leak / loop tests).
		// Stream listens (TCP-LISTEN,fork PIPE) transfer directly — a bridge would
		// open -r/-R sniff files twice per session (VARS_IN_SNIFFPATH expects 4 files
		// for 2 clients, not 8).
		if needsForkSocketpair(lo) {
			sp0, sp1, spErr := unixSocketpairLogged(cg)
			if spErr != nil {
				cg.Log.Errorf("socketpair: %s", spErr)
				logx.CloseQuiet(ro)
				return
			}
			go func() {
				defer func() { _ = sp1.Close() }()
				defer func() { _ = ro.Close() }()
				_ = transferStreams(ctx, FileStream(sp1), ro.EffectiveStream(), cg)
			}()
			defer func() { _ = sp0.Close() }()
			if err := transferStreams(ctx, leftStream, FileStream(sp0), cg); err != nil {
				cg.Log.Debugf("transfer: %s", err)
			}
			return
		}
		defer func() { _ = ro.Close() }()
		if err := transferStreams(ctx, leftStream, ro.EffectiveStream(), cg); err != nil {
			cg.Log.Debugf("transfer: %s", err)
		}
	})
}

// needsForkSocketpair is true for datagram RECVFROM,fork (classic creates a
// socketpair per child). Stream acceptors transfer the accepted conn directly.
func needsForkSocketpair(lo *Opened) bool {
	if lo == nil {
		return false
	}
	lab := strings.ToUpper(lo.Label)
	return strings.Contains(lab, "RECVFROM")
}

func runForkListenRight(ctx context.Context, lo, ro *Opened, g *Global) error {
	ln := ro.Listener
	left := lo.EffectiveStream()
	// Shared left (e.g. FILE,o-append) must stay open across all fork children.
	// Classic max-children + -U FILE:... LISTEN,fork appends each session in order.
	// max-children applies to the listen address (right side here).
	// Shared left stream (FILE append, EXEC end-close) cannot safely run concurrent
	// bidirectional transfers on one FD pair — serialize accept sessions.
	// sessionWrap.Close pokes a short deadline and returns immediately; the next
	// wrap, started only after Transfer returns, clears that leftover.
	var leftMu sync.Mutex
	go func() {
		<-ctx.Done()
		logx.CloseQuiet(ln)
	}()
	return ro.forEachAccepted(ctx, ln, g, false, func(c net.Conn, cg *Global) {
		// Serialize sessions on the shared left stream.
		leftMu.Lock()
		defer leftMu.Unlock()
		if err := RememberTLSPeer(cg, c, ro.HandshakeTimeout); err != nil {
			cg.Log.Errorf("handshake: %s", err)
			return
		}
		rightStream, err := streamFromDial(ro, c)
		if err != nil {
			cg.Log.Errorf("wrap accept: %s", err)
			return
		}
		// noCloseLeft=true: do not close/shutdown shared left between children.
		if err := transferStreamsOpts(ctx, left, rightStream, cg, true, false); err != nil {
			cg.Log.Debugf("transfer: %s", err)
		}
	})
}

func transferPair(ctx context.Context, lo, ro *Opened, g *Global) error {
	return transferStreams(ctx, lo.EffectiveStream(), ro.EffectiveStream(), g)
}

func transferStreams(ctx context.Context, left, right relay.Stream, g *Global) error {
	return transferStreamsOpts(ctx, left, right, g, StreamIsEndClose(left), StreamIsEndClose(right))
}

func transferStreamsOpts(ctx context.Context, left, right relay.Stream, g *Global, noCloseLeft, noCloseRight bool) error {
	if left == nil || right == nil {
		return fmt.Errorf("nil stream")
	}
	WaitFromEnv("SOCAT_TRANSFER_WAIT")
	// Classic opens -r/-R sniff files at transfer start (after peer env is set).
	if g != nil && (g.RawLeftPath != "" || g.RawRightPath != "") {
		if err := openSniffFiles(g); err != nil {
			return err
		}
		defer func() {
			if g.RawLeft != nil {
				_ = g.RawLeft.Close()
				g.RawLeft = nil
			}
			if g.RawRight != nil {
				_ = g.RawRight.Close()
				g.RawRight = nil
			}
		}()
	}
	leftToRight, rightToLeft := g.LeftToRight, g.RightToLeft
	if !leftToRight && !rightToLeft {
		leftToRight, rightToLeft = true, true
	}
	cfg := relay.Config{
		BufferSize:   g.BlockSize,
		Linger:       g.Linger,
		IdleTimeout:  g.Idle,
		LeftToRight:  leftToRight,
		RightToLeft:  rightToLeft,
		Verbose:      g.Verbose,
		Hex:          g.Hex,
		Dump:         g.Dump,
		NoCloseLeft:  noCloseLeft,
		NoCloseRight: noCloseRight,
	}
	// Assign only concrete dump files. Converting a nil *os.File directly to
	// io.Writer produces a non-nil interface that reports spurious write errors.
	if g.RawLeft != nil {
		cfg.RawLeft = g.RawLeft
	}
	if g.RawRight != nil {
		cfg.RawRight = g.RawRight
	}
	if g != nil && g.Statistics && g.Log != nil {
		cfg.OnStats = func(st relay.Stats) {
			PrintStats(g.Log, st, cfg.LeftToRight, cfg.RightToLeft, true)
			g.markStatsPrinted()
		}
	}
	// Classic MULTIPLE_EOF greps: "socket 2 (fd .*) is at EOF" (Notice once per side).
	if g != nil && g.Log != nil {
		var eofOnce [3]sync.Once // index 1 and 2
		cfg.OnEOF = func(sock, fd int) {
			if sock < 1 || sock > 2 {
				return
			}
			eofOnce[sock].Do(func() {
				if fd < 0 {
					fd = 0
				}
				g.Log.Noticef("socket %d (fd %d) is at EOF", sock, fd)
			})
		}
	}
	return relay.Transfer(ctx, left, right, cfg)
}

// DefaultCreateMode is classic open/creat/mkfifo mode (0666 before umask).
const DefaultCreateMode os.FileMode = 0o666

// ParseFileMode applies perm= or mode= (octal, classic TYPE_MODET), else def.
func ParseFileMode(s parse.Spec, def os.FileMode) (os.FileMode, error) {
	m, ok, err := explicitFileMode(s)
	if err != nil {
		return 0, err
	}
	if ok {
		return m, nil
	}
	return def, nil
}

// explicitFileMode returns perm= or mode= when set (octal, classic TYPE_MODET).
func explicitFileMode(s parse.Spec) (os.FileMode, bool, error) {
	name := "perm"
	v := s.OptionValue("perm", "")
	if v == "" {
		name = "mode"
		v = s.OptionValue("mode", "")
	}
	if v == "" {
		return 0, false, nil
	}
	m, err := strconv.ParseUint(v, 8, 32)
	if err != nil {
		var m2 uint64
		if _, e := fmt.Sscanf(v, "%o", &m2); e != nil {
			return 0, false, fmt.Errorf("invalid %s %q", name, v)
		}
		m = m2
	}
	return os.FileMode(m), true, nil
}

// ApplyPerm sets exact permissions after create/open (classic fchmod/chmod).
// Open create modes are still masked by umask; perm= forces the final mode.
func ApplyPerm(path string, s parse.Spec, f *os.File) error {
	mode, ok, err := explicitFileMode(s)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if f != nil {
		if err := f.Chmod(mode); err != nil {
			// Some paths (e.g. some PTY slaves) reject fchmod; try path.
			if path != "" {
				return os.Chmod(path, mode)
			}
			return err
		}
		return nil
	}
	if path == "" {
		return nil
	}
	return os.Chmod(path, mode)
}
