package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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

	// Open left first.
	lo, err := OpenChannel(ctx, left, lMode, g)
	if err != nil {
		// Preserve "unknown device/address" text.
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
		// Client CONNECT/TLS-CONNECT with fork.
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

// runConnectFork is the CONNECT,fork parent loop: dial, spawn child
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
		err = transferStreams(cctx, left, ro.EffectiveStream(), cg)
		waitForkChild(cctx, lo.MaxChildren, ro)
		return err
	})
}

func waitForkChild(ctx context.Context, maxChildren int, opened *Opened) {
	if maxChildren <= 0 || opened == nil || opened.childDone == nil {
		return
	}
	select {
	case <-opened.childDone:
	case <-ctx.Done():
	}
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
	slots := newChildSlots(o.MaxChildren)
	var children sync.WaitGroup
	defer children.Wait()
	for {
		if !slots.acquire(ctx) {
			return nil
		}
		conn, err := AcceptWithTimeout(ctx, ln, o.AcceptTimeout)
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
		if o.PeerFilter != nil {
			if ferr := o.PeerFilter(conn); ferr != nil {
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
		children.Add(1)
		go func(c net.Conn) {
			defer children.Done()
			defer func() { _ = c.Close() }()
			defer slots.release()
			stopClose := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stopClose()
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
			// No "right address:" prefix on the open error.
			cg.Log.Errorf("%s", err)
			return
		}
		// RECVFROM,fork creates a socketpair per child. Stream listens
		// (TCP-LISTEN,fork PIPE) transfer directly — a bridge would open
		// -r/-R sniff files twice per session.
		if needsForkSocketpair(lo) {
			sp0, sp1, spErr := unixSocketpairLogged(cg)
			if spErr != nil {
				cg.Log.Errorf("socketpair: %s", spErr)
				logx.CloseQuiet(ro)
				return
			}
			bridgeDone := make(chan struct{})
			go func() {
				defer close(bridgeDone)
				defer func() { _ = sp1.Close() }()
				defer func() { _ = ro.Close() }()
				_ = transferStreams(ctx, FileStream(sp1), ro.EffectiveStream(), cg)
				waitForkChild(ctx, lo.MaxChildren, ro)
			}()
			defer func() { _ = sp0.Close() }()
			if err := transferStreams(ctx, leftStream, FileStream(sp0), cg); err != nil {
				cg.Log.Debugf("transfer: %s", err)
			}
			<-bridgeDone
			return
		}
		defer func() { _ = ro.Close() }()
		if err := transferStreams(ctx, leftStream, ro.EffectiveStream(), cg); err != nil {
			cg.Log.Debugf("transfer: %s", err)
		}
		waitForkChild(ctx, lo.MaxChildren, ro)
	})
}

// needsForkSocketpair is true for datagram RECVFROM,fork (a socketpair per
// child). Stream acceptors transfer the accepted conn directly.
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
	// max-children applies to the listen address (right side here).
	// Shared left stream (FILE append, EXEC socketpair with end-close) cannot
	// safely run concurrent bidirectional transfers on one FD pair — serialize
	// accept sessions. sessionWrap.Close pokes a short deadline and returns
	// immediately; the next wrap, started only after Transfer returns, clears
	// that leftover. end-close still uses socketpair (not pipes).
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
	// Open -r/-R sniff files at transfer start (after peer env is set).
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
	// Notice once per side: "socket N (fd M) is at EOF".
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

// DefaultCreateMode is open/creat/mkfifo mode (0666 before umask).
const DefaultCreateMode os.FileMode = 0o666

// ParseFileMode applies perm= or mode= (octal), else def.
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

// explicitFileMode returns perm= or mode= when set (octal).
func explicitFileMode(s parse.Spec) (os.FileMode, bool, error) {
	m, ok, err := explicitUnixMode(s)
	if err != nil || !ok {
		return 0, ok, err
	}
	return UnixModeToFileMode(m), true, nil
}

// ApplyPerm sets exact permissions on named sockets and PTY slaves after bind.
// Regular files use perm=/mode= as the open(2) mode instead, so umask still applies.
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

// ApplyNamedAttrs applies perm/user/group to a filesystem name in
// command-line order: each perm=/mode= is chmod of the name, each
// user=/uid=/owner= is chown(uid,-1), each group=/gid= is chown(-1,gid).
// Order matters for setuid/setgid (`user=,perm=04755` keeps setuid; reverse
// clears it). Regular files and FIFOs pass perm= to open(2)/mkfifo so umask
// still applies; do not use ApplyNamedAttrs as create-mode for those.
func ApplyNamedAttrs(path string, s parse.Spec, f *os.File) error {
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "perm":
			if err := applyNamedPerm(path, f, o); err != nil {
				return err
			}
		case "user":
			if err := applyNamedUser(path, f, o); err != nil {
				return err
			}
		case "group":
			if err := applyNamedGroup(path, f, o); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyNamedPerm(path string, f *os.File, o parse.Option) error {
	if !o.Has {
		return fmt.Errorf("%s: invalid value %q", o.OriginalSpelling(), o.Value)
	}
	mode, err := parseModeT(o.OriginalSpelling(), o.Value)
	if err != nil {
		return err
	}
	noteLifecycleSyscall("chmod")
	if path != "" {
		return os.Chmod(path, mode)
	}
	if f != nil {
		return f.Chmod(mode)
	}
	return nil
}

func applyNamedUser(path string, f *os.File, o parse.Option) error {
	v, err := requiredLifecycleOptionValue(o)
	if err != nil {
		return err
	}
	uid, hasU, err := resolveUID(v)
	if err != nil {
		return err
	}
	if !hasU {
		return nil
	}
	noteLifecycleSyscall("chown")
	return namedChown(path, f, uid, -1)
}

func applyNamedGroup(path string, f *os.File, o parse.Option) error {
	v, err := requiredLifecycleOptionValue(o)
	if err != nil {
		return err
	}
	gid, hasG, err := resolveGID(v)
	if err != nil {
		return err
	}
	if !hasG {
		return nil
	}
	noteLifecycleSyscall("chown")
	return namedChown(path, f, -1, gid)
}

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
