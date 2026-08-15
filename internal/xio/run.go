package xio

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

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

	// Client CONNECT/OPENSSL-CONNECT with fork,max-children (classic xio-ipapp loop).
	// Parent only dials; each child opens the peer address and transfers.
	if lo.ConnectFork {
		return runConnectFork(ctx, lo, right, rMode, g)
	}

	// Left EXEC,nofork: need right open first, then exec on right's stream.
	if lo.NoForkSpec != nil {
		ro, err := OpenChannel(ctx, right, rMode, g)
		if err != nil {
			return err
		}
		defer ro.Close()
		return runExecNoFork(ctx, ro.EffectiveStream(), *lo.NoForkSpec, g, lMode)
	}

	ro, err := OpenChannel(ctx, right, rMode, g)
	if err != nil {
		return err
	}
	defer ro.Close()

	// Right EXEC,nofork on left stream (TCP-LISTEN + EXEC,nofork; or STDIO + EXEC,nofork).
	if ro.NoForkSpec != nil {
		return runExecNoFork(ctx, lo.EffectiveStream(), *ro.NoForkSpec, g, rMode)
	}

	if ro.Fork && ro.Listener != nil {
		// Unusual: listen on right — classic still works; handle accept loop with left already open
		return runForkListenRight(ctx, lo, ro, g)
	}

	if ro.ConnectFork {
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

// unixSocketpairLogged creates AF_UNIX SOCK_STREAM pair and logs classic
// `I socketpair(1, 1, 0, {a,b}) -> 0` (RECVFROM_FORK_LEAK).
func unixSocketpairLogged(g *Global) (a, b *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	// Classic CLOEXEC on both ends after logging the numbers.
	if g != nil && g.Log != nil {
		g.Log.Infof("Generating socketpair that triggers parent when packet has been consumed")
		g.Log.Infof("socketpair(1, 1, 0, {%d,%d}) -> 0", fds[0], fds[1])
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return os.NewFile(uintptr(fds[0]), "sp0"), os.NewFile(uintptr(fds[1]), "sp1"), nil
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
		defer ro.Close()
		return transferStreams(cctx, left, ro.EffectiveStream(), cg)
	})
}

// runConnectForkWithLeft handles CONNECT,fork on the right address with left
// already open (shared stream; sessions serialized).
func runConnectForkWithLeft(ctx context.Context, left relay.Stream, ro *Opened, g *Global) error {
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

func runConnectForkLoop(ctx context.Context, o *Opened, g *Global, child func(context.Context, *Global, net.Conn) error) error {
	if o.Dial == nil {
		return fmt.Errorf("%s: connect fork without dialer", o.Label)
	}
	interval := o.Interval
	if interval <= 0 {
		interval = time.Second
	}
	var slots chan struct{}
	if o.MaxChildren > 0 {
		slots = make(chan struct{}, o.MaxChildren)
	}
	if g != nil && g.Log != nil {
		g.Log.Noticef("starting connect loop (%s)", o.Label)
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		// Wait for a free child slot before dial (classic: parent blocks when
		// num_child >= max-children, then connects again).
		if slots != nil {
			select {
			case <-ctx.Done():
				return nil
			case slots <- struct{}{}:
			}
		}
		conn, err := o.Dial(ctx)
		if err != nil {
			if slots != nil {
				<-slots
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if g != nil && g.Log != nil {
			g.Log.Infof("successfully connected from %s to %s", conn.LocalAddr(), conn.RemoteAddr())
		}
		go func(c net.Conn) {
			defer c.Close()
			if slots != nil {
				defer func() { <-slots }()
			}
			cg := *g
			RememberAddrs(&cg, c)
			RememberTLSPeer(&cg, c)
			if err := child(ctx, &cg, c); err != nil {
				if g != nil && g.Log != nil {
					g.Log.Debugf("connect child: %s", err)
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
				CloseRefusedPeer(conn)
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
			RememberAddrs(&cg, c)
			leftStream, err := streamFromDial(lo, c)
			if err != nil {
				g.Log.Errorf("wrap accept: %s", err)
				return
			}
			ro, err := OpenChannel(ctx, right, rMode, &cg)
			if err != nil {
				// Classic greps `E open(` for RECVFROM_FORK_LOOP — no "right address:" prefix.
				g.Log.Errorf("%s", err)
				return
			}
			// Classic RECVFROM,fork creates a socketpair per child (FD-leak / loop tests).
			// Stream listens (TCP-LISTEN,fork PIPE) transfer directly — a bridge would
			// open -r/-R sniff files twice per session (VARS_IN_SNIFFPATH expects 4 files
			// for 2 clients, not 8).
			if needsForkSocketpair(lo) {
				sp0, sp1, spErr := unixSocketpairLogged(g)
				if spErr != nil {
					g.Log.Errorf("socketpair: %s", spErr)
					ro.Close()
					return
				}
				go func() {
					defer sp1.Close()
					defer ro.Close()
					_ = transferStreams(ctx, FileStream(sp1), ro.EffectiveStream(), &cg)
				}()
				defer sp0.Close()
				if err := transferStreams(ctx, leftStream, FileStream(sp0), &cg); err != nil {
					g.Log.Debugf("transfer: %s", err)
				}
				return
			}
			defer ro.Close()
			if err := transferStreams(ctx, leftStream, ro.EffectiveStream(), &cg); err != nil {
				g.Log.Debugf("transfer: %s", err)
			}
		}(conn)
	}
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
	// Shared left stream (FILE append, EXEC end-close) cannot safely run concurrent
	// bidirectional transfers on one FD pair — serialize accept sessions.
	var leftMu sync.Mutex
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
				CloseRefusedPeer(conn)
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
			leftMu.Lock()
			defer leftMu.Unlock()
			cg := *g
			RememberAddrs(&cg, c)
			rightStream, err := streamFromDial(ro, c)
			if err != nil {
				g.Log.Errorf("wrap accept: %s", err)
				return
			}
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
	return transferStreamsOpts(ctx, left, right, g, StreamIsEndClose(left), StreamIsEndClose(right))
}

func transferStreamsOpts(ctx context.Context, left, right relay.Stream, g *Global, noCloseLeft, noCloseRight bool) error {
	if left == nil || right == nil {
		return fmt.Errorf("nil stream")
	}
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
	cfg := relay.Config{
		BufferSize:   g.BlockSize,
		Linger:       g.Linger,
		IdleTimeout:  g.Idle,
		LeftToRight:  g.LeftToRight || (!g.LeftToRight && !g.RightToLeft),
		RightToLeft:  g.RightToLeft || (!g.LeftToRight && !g.RightToLeft),
		Verbose:      g.Verbose,
		Hex:          g.Hex,
		Dump:         g.Dump,
		RawLeft:      g.RawLeft,
		RawRight:     g.RawRight,
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
	if g != nil && g.Statistics && g.Log != nil {
		cfg.OnStats = func(st relay.Stats) {
			PrintStats(g.Log, st, cfg.LeftToRight, cfg.RightToLeft, true)
			g.statsPrinted.Store(true)
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

// Apply common file mode from options (octal string).
// Classic accepts both perm= and mode= (TYPE_MODET, octal).
func ParseFileMode(s parse.Spec, def os.FileMode) os.FileMode {
	if m, ok := explicitFileMode(s); ok {
		return m
	}
	return def
}

// explicitFileMode returns perm= or mode= when set (octal, classic TYPE_MODET).
func explicitFileMode(s parse.Spec) (os.FileMode, bool) {
	v := s.OptionValue("perm", "")
	if v == "" {
		v = s.OptionValue("mode", "")
	}
	if v == "" {
		return 0, false
	}
	// Prefer pure octal (perm=511, mode=644); allow 0-prefix.
	m, err := strconv.ParseUint(v, 8, 32)
	if err != nil {
		var m2 uint64
		if _, e := fmt.Sscanf(v, "%o", &m2); e != nil {
			return 0, false
		}
		m = m2
	}
	return os.FileMode(m), true
}

// ApplyPerm sets exact permissions after create/open (classic fchmod/chmod).
// Open create modes are still masked by umask; perm= forces the final mode.
func ApplyPerm(path string, s parse.Spec, f *os.File) error {
	mode, ok := explicitFileMode(s)
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
