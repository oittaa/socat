//go:build linux

package posixmqopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/netopen"
	"golang.org/x/sys/unix"
)

const (
	mqObserve = 350 * time.Millisecond
	mqStuck   = 2 * time.Second
)

func armMQWait(t *testing.T) <-chan struct{} {
	t.Helper()
	entered := make(chan struct{})
	var once sync.Once
	hook := mqWaitHook(func() { once.Do(func() { close(entered) }) })
	mqWaitEntered.Store(&hook)
	t.Cleanup(func() { mqWaitEntered.CompareAndSwap(&hook, nil) })
	return entered
}

func waitMQWait(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(mqStuck):
		t.Fatal("operation did not enter MQ wait")
	}
}

func openSpec(t *testing.T, spec string, mode xio.Mode) *xio.Opened {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	o, err := xio.OpenChannel(ctx, ch, mode, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func setReadDL(t *testing.T, st relay.Stream, deadline time.Time) {
	t.Helper()
	ok, err := relay.SetStreamReadDeadline(st, deadline)
	if !ok {
		t.Fatal("no SetReadDeadline")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func setWriteDL(t *testing.T, st relay.Stream, deadline time.Time) {
	t.Helper()
	ok, err := relay.SetStreamWriteDeadline(st, deadline)
	if !ok {
		t.Fatal("no SetWriteDeadline")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func setBothDL(t *testing.T, st relay.Stream, deadline time.Time) {
	t.Helper()
	setReadDL(t, st, deadline)
	setWriteDL(t, st, deadline)
}

func mqCurmsgs(t *testing.T, q string) int {
	t.Helper()
	fd, err := mqOpen(q, unix.O_RDONLY, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mqClose(fd) }()
	var attr mqAttr
	if err := mqGetattr(fd, &attr); err != nil {
		t.Fatal(err)
	}
	return int(attr.Curmsgs)
}

func sendRaw(t *testing.T, q, msg string) {
	t.Helper()
	fd, err := mqOpen(q, unix.O_WRONLY|unix.O_CREAT, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mqClose(fd) }()
	if err := mqTimedSend(fd, []byte(msg), 0, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func drainRaw(t *testing.T, q string) {
	t.Helper()
	fd, err := mqOpen(q, unix.O_RDONLY, 0, nil)
	if err != nil {
		return
	}
	defer func() { _ = mqClose(fd) }()
	buf := make([]byte, 256)
	_, _ = mqTimedReceive(fd, buf, nil, time.Now().Add(100*time.Millisecond))
}

func waitUnix(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("unix listener %s did not appear", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type deadlineKind int

const (
	dlPast deadlineKind = iota
	dlShorten
	dlExtend
	dlClear
	dlBothPast
)

func (k deadlineKind) String() string {
	switch k {
	case dlPast:
		return "set_past"
	case dlShorten:
		return "shorten_50ms"
	case dlExtend:
		return "extend_180ms"
	case dlClear:
		return "clear"
	case dlBothPast:
		return "setdeadline_past"
	default:
		return "unknown"
	}
}

type blockedOp struct {
	errc     <-chan error
	release  func()
	setRead  func(time.Time)
	setWrite func(time.Time)
	setBoth  func(time.Time)
}

func startBlockedRead(t *testing.T, q string) blockedOp {
	t.Helper()
	o := openSpec(t, fmt.Sprintf("POSIXMQ-READ:%s,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeRead)
	st := o.EffectiveStream()
	return startBlockedStreamRead(t, st, func() { sendRaw(t, q, "wake") })
}

func startBlockedWrite(t *testing.T, q string) blockedOp {
	t.Helper()
	o := openSpec(t, fmt.Sprintf("POSIXMQ-WRITE:%s,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeWrite)
	st := o.EffectiveStream()
	if _, err := st.Write([]byte("full")); err != nil {
		t.Fatal(err)
	}
	return startBlockedStreamWrite(t, st, func() { drainRaw(t, q) })
}

func startBlockedSendFork(t *testing.T, q string) blockedOp {
	t.Helper()
	o := openSpec(t, fmt.Sprintf("POSIXMQ-SEND:%s,fork,mq-maxmsg=1,mq-msgsize=64,unlink-early", q), xio.ModeWrite)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := o.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("full")); err != nil {
		t.Fatal(err)
	}
	entered := armMQWait(t)
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("blocked"))
		errc <- err
	}()
	waitMQWait(t, entered)
	return blockedOp{
		errc:    errc,
		release: func() { drainRaw(t, q) },
		setRead: func(tm time.Time) {
			if err := conn.SetReadDeadline(tm); err != nil {
				t.Fatal(err)
			}
		},
		setWrite: func(tm time.Time) {
			if err := conn.SetWriteDeadline(tm); err != nil {
				t.Fatal(err)
			}
		},
		setBoth: func(tm time.Time) {
			if err := conn.SetDeadline(tm); err != nil {
				t.Fatal(err)
			}
		},
	}
}

func startBlockedStreamRead(t *testing.T, st relay.Stream, release func()) blockedOp {
	t.Helper()
	entered := armMQWait(t)
	errc := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 64))
		errc <- err
	}()
	waitMQWait(t, entered)
	return blockedOp{
		errc:     errc,
		release:  release,
		setRead:  func(tm time.Time) { setReadDL(t, st, tm) },
		setWrite: func(tm time.Time) { setWriteDL(t, st, tm) },
		setBoth:  func(tm time.Time) { setBothDL(t, st, tm) },
	}
}

func startBlockedStreamWrite(t *testing.T, st relay.Stream, release func()) blockedOp {
	t.Helper()
	entered := armMQWait(t)
	errc := make(chan error, 1)
	go func() {
		_, err := st.Write([]byte("blocked"))
		errc <- err
	}()
	waitMQWait(t, entered)
	return blockedOp{
		errc:     errc,
		release:  release,
		setRead:  func(tm time.Time) { setReadDL(t, st, tm) },
		setWrite: func(tm time.Time) { setWriteDL(t, st, tm) },
		setBoth:  func(tm time.Time) { setBothDL(t, st, tm) },
	}
}

func (op blockedOp) finishOrRelease(t *testing.T, done *atomic.Bool) {
	t.Helper()
	t.Cleanup(func() {
		if done.Load() {
			return
		}
		op.release()
		select {
		case <-op.errc:
		case <-time.After(mqStuck):
		}
	})
}

func runDeadlineCase(t *testing.T, kind deadlineKind, write bool, op blockedOp) {
	t.Helper()
	var done atomic.Bool
	op.finishOrRelease(t, &done)

	apply := op.setRead
	if write {
		apply = op.setWrite
	}
	switch kind {
	case dlPast:
		apply(time.Now().Add(-time.Millisecond))
		op.mustTimeout(t, mqObserve)
	case dlBothPast:
		op.setBoth(time.Now().Add(-time.Millisecond))
		op.mustTimeout(t, mqObserve)
	case dlShorten:
		apply(time.Now().Add(50 * time.Millisecond))
		op.mustTimeout(t, mqObserve)
	case dlExtend:
		apply(time.Now().Add(180 * time.Millisecond))
		time.Sleep(10 * time.Millisecond)
		apply(time.Now().Add(2 * time.Second))
		op.mustStayBlocked(t, mqObserve)
		apply(time.Now().Add(-time.Millisecond))
		op.mustTimeout(t, mqObserve)
	case dlClear:
		apply(time.Now().Add(180 * time.Millisecond))
		time.Sleep(10 * time.Millisecond)
		apply(time.Time{})
		op.mustStayBlocked(t, mqObserve)
		apply(time.Now().Add(-time.Millisecond))
		op.mustTimeout(t, mqObserve)
	}
	done.Store(true)
}

func (op blockedOp) mustTimeout(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case err := <-op.errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) && !os.IsTimeout(err) {
			t.Fatalf("err=%v want deadline exceeded", err)
		}
	case <-time.After(wait):
		t.Fatalf("pending I/O still blocked after %v", wait)
	}
}

func (op blockedOp) mustStayBlocked(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case err := <-op.errc:
		t.Fatalf("pending I/O returned early: %v", err)
	case <-time.After(wait):
	}
}

func TestPOSIXMQEndpointDeadlines(t *testing.T) {
	kinds := []deadlineKind{dlPast, dlShorten, dlExtend, dlClear, dlBothPast}
	for _, kind := range kinds {
		t.Run("read_"+kind.String(), func(t *testing.T) {
			q := testQueue(t)
			runDeadlineCase(t, kind, false, startBlockedRead(t, q))
		})
		t.Run("write_"+kind.String(), func(t *testing.T) {
			q := testQueue(t)
			runDeadlineCase(t, kind, true, startBlockedWrite(t, q))
		})
		t.Run("send_fork_"+kind.String(), func(t *testing.T) {
			q := testQueue(t)
			runDeadlineCase(t, kind, true, startBlockedSendFork(t, q))
		})
	}
}

func TestPOSIXMQIndependentDeadlines(t *testing.T) {
	t.Run("write_deadline_leaves_read", func(t *testing.T) {
		q := testQueue(t)
		o := openSpec(t, fmt.Sprintf("POSIXMQ-BIDIRECTIONAL:%s,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeRDWR)
		op := startBlockedStreamRead(t, o.EffectiveStream(), func() { sendRaw(t, q, "wake") })
		var done atomic.Bool
		op.finishOrRelease(t, &done)
		op.setWrite(time.Now().Add(-time.Millisecond))
		op.mustStayBlocked(t, 200*time.Millisecond)
		op.setRead(time.Now().Add(-time.Millisecond))
		op.mustTimeout(t, mqObserve)
		done.Store(true)
	})
	t.Run("read_deadline_leaves_write", func(t *testing.T) {
		q := testQueue(t)
		o := openSpec(t, fmt.Sprintf("POSIXMQ-BIDIRECTIONAL:%s,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeRDWR)
		st := o.EffectiveStream()
		if _, err := st.Write([]byte("full")); err != nil {
			t.Fatal(err)
		}
		op := startBlockedStreamWrite(t, st, func() { drainRaw(t, q) })
		var done atomic.Bool
		op.finishOrRelease(t, &done)
		op.setRead(time.Now().Add(-time.Millisecond))
		op.mustStayBlocked(t, 200*time.Millisecond)
		op.setWrite(time.Now().Add(-time.Millisecond))
		op.mustTimeout(t, mqObserve)
		done.Store(true)
	})
}

func TestPOSIXMQDeadlineFutureOp(t *testing.T) {
	q := testQueue(t)
	o := openSpec(t, fmt.Sprintf("POSIXMQ-READ:%s,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeRead)
	st := o.EffectiveStream()
	setReadDL(t, st, time.Now().Add(-time.Millisecond))
	_, err := st.Read(make([]byte, 64))
	if !errors.Is(err, os.ErrDeadlineExceeded) && !os.IsTimeout(err) {
		t.Fatalf("first Read err=%v want timeout", err)
	}
	setReadDL(t, st, time.Time{})
	sendRaw(t, q, "later")
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "later" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestPOSIXMQDescriptorReuse(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		q := testQueue(t)
		o := openSpec(t, fmt.Sprintf("POSIXMQ-READ:%s,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeRead)
		st := o.EffectiveStream()
		entered := armMQWait(t)
		type result struct {
			n   int
			msg []byte
			err error
		}
		got := make(chan result, 1)
		buf := make([]byte, 64)
		go func() {
			n, err := st.Read(buf)
			got <- result{n: n, err: err, msg: append([]byte(nil), buf[:n]...)}
		}()
		waitMQWait(t, entered)

		if err := o.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		rep := testQueue(t)
		sendRaw(t, rep, "foreign-queue-data")

		select {
		case r := <-got:
			if string(r.msg) == "foreign-queue-data" && r.err == nil {
				t.Fatal("pending Read returned replacement queue data")
			}
			if r.err == nil {
				t.Fatalf("pending Read succeeded with %q", r.msg)
			}
		case <-time.After(mqStuck):
			sendRaw(t, q, "wake")
			<-got
			t.Fatal("pending Read did not return after Close")
		}
		if mqCurmsgs(t, rep) != 1 {
			t.Fatal("replacement queue message was consumed")
		}
	})

	t.Run("write", func(t *testing.T) {
		q := testQueue(t)
		o := openSpec(t, fmt.Sprintf("POSIXMQ-WRITE:%s,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeWrite)
		st := o.EffectiveStream()
		if _, err := st.Write([]byte("full")); err != nil {
			t.Fatal(err)
		}
		entered := armMQWait(t)
		errc := make(chan error, 1)
		go func() { _, err := st.Write([]byte("blocked")); errc <- err }()
		waitMQWait(t, entered)

		if err := o.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		rep := testQueue(t)
		attr := mqAttr{Maxmsg: 1, Msgsize: 64}
		rfd, err := mqOpen(rep, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600, &attr)
		if err != nil {
			t.Fatal(err)
		}
		_ = mqClose(rfd)

		select {
		case err := <-errc:
			if err == nil {
				t.Fatal("pending Write succeeded after Close")
			}
		case <-time.After(mqStuck):
			drainRaw(t, q)
			<-errc
			t.Fatal("pending Write did not return after Close")
		}
		if mqCurmsgs(t, rep) != 0 {
			t.Fatal("pending Write inserted into the replacement queue")
		}
	})
}

func TestPOSIXMQListenerDescriptorReuse(t *testing.T) {
	q := testQueue(t)
	o := openSpec(t, fmt.Sprintf("POSIXMQ-RECV:%s,fork,unlink-early,mq-maxmsg=2,mq-msgsize=64", q), xio.ModeRead)
	if o.Listener == nil {
		t.Fatal("missing listener")
	}
	entered := armMQWait(t)
	errc := make(chan error, 1)
	var accepted net.Conn
	go func() {
		c, err := o.Listener.Accept()
		accepted = c
		errc <- err
	}()
	waitMQWait(t, entered)

	if err := o.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	rep := testQueue(t)
	sendRaw(t, rep, "foreign-queue-data")

	select {
	case err := <-errc:
		if err == nil {
			if accepted != nil {
				_ = accepted.Close()
			}
			t.Fatal("Accept succeeded after Close")
		}
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, unix.EBADF) {
			t.Fatalf("Accept err=%v want closed", err)
		}
	case <-time.After(mqStuck):
		sendRaw(t, q, "wake")
		<-errc
		t.Fatal("Accept did not return after Close")
	}
	if mqCurmsgs(t, rep) != 1 {
		t.Fatal("Accept consumed the replacement queue message")
	}
}

func TestPOSIXMQSharedForkCancellation(t *testing.T) {
	t.Run("write", func(t *testing.T) {
		q := testQueue(t)
		attr := mqAttr{Maxmsg: 1, Msgsize: 64}
		fd, err := mqOpen(q, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600, &attr)
		if err != nil {
			t.Fatal(err)
		}
		if err := mqTimedSend(fd, []byte("full"), 0, time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		_ = mqClose(fd)

		path := filepath.Join(t.TempDir(), "mq.sock")
		left, err := parse.ParseChannel(fmt.Sprintf("POSIXMQ-WRITE:%s,mq-maxmsg=1,mq-msgsize=64", q))
		if err != nil {
			t.Fatal(err)
		}
		right, err := parse.ParseChannel("UNIX-LISTEN:" + path + ",unlink-early,fork,max-children=1")
		if err != nil {
			t.Fatal(err)
		}
		g := testGlobal()
		g.RightToLeft = true
		g.LeftToRight = false
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errc := make(chan error, 1)
		go func() { errc <- xio.Run(ctx, left, right, g) }()
		waitUnix(t, path)

		entered := armMQWait(t)
		cli, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cli.Close() }()
		if _, err := cli.Write([]byte("second")); err != nil {
			t.Fatal(err)
		}
		waitMQWait(t, entered)
		start := time.Now()
		cancel()
		select {
		case <-errc:
			if elapsed := time.Since(start); elapsed > 600*time.Millisecond {
				t.Fatalf("shared-fork write cancel took %v", elapsed)
			}
		case <-time.After(600 * time.Millisecond):
			drainRaw(t, q)
			<-errc
			t.Fatal("shared-fork write stayed blocked after cancel")
		}

		drainRaw(t, q)
		sendRaw(t, q, "after")
		ro := openSpec(t, "POSIXMQ-READ:"+q, xio.ModeRead)
		buf := make([]byte, 64)
		n, err := ro.EffectiveStream().Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "after" {
			t.Fatalf("following session got %q", buf[:n])
		}
	})

	t.Run("read", func(t *testing.T) {
		q := testQueue(t)
		path := filepath.Join(t.TempDir(), "mq.sock")
		left, err := parse.ParseChannel(fmt.Sprintf("POSIXMQ-READ:%s,mq-maxmsg=1,mq-msgsize=64,unlink-early", q))
		if err != nil {
			t.Fatal(err)
		}
		right, err := parse.ParseChannel("UNIX-LISTEN:" + path + ",unlink-early,fork,max-children=1")
		if err != nil {
			t.Fatal(err)
		}
		g := testGlobal()
		g.LeftToRight = true
		g.RightToLeft = false
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errc := make(chan error, 1)
		go func() { errc <- xio.Run(ctx, left, right, g) }()
		waitUnix(t, path)

		entered := armMQWait(t)
		cli, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cli.Close() }()
		waitMQWait(t, entered)
		start := time.Now()
		cancel()
		select {
		case <-errc:
			if elapsed := time.Since(start); elapsed > 600*time.Millisecond {
				t.Fatalf("shared-fork read cancel took %v", elapsed)
			}
		case <-time.After(600 * time.Millisecond):
			sendRaw(t, q, "wake")
			<-errc
			t.Fatal("shared-fork read stayed blocked after cancel")
		}
	})
}

func TestPOSIXMQOwnedCancelUnblocks(t *testing.T) {
	q := testQueue(t)
	left, err := parse.ParseChannel(fmt.Sprintf("POSIXMQ-READ:%s,mq-maxmsg=1,mq-msgsize=64,unlink-early", q))
	if err != nil {
		t.Fatal(err)
	}
	right, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	g := testGlobal()
	g.LeftToRight = true
	g.RightToLeft = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- xio.Run(ctx, left, right, g) }()
	entered := armMQWait(t)
	waitMQWait(t, entered)
	start := time.Now()
	cancel()
	select {
	case <-errc:
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("owned cancel took %v", elapsed)
		}
	case <-time.After(mqStuck):
		sendRaw(t, q, "wake")
		<-errc
		t.Fatal("owned cancel did not unblock MQ read")
	}
}

func TestPOSIXMQNonblockStillImmediate(t *testing.T) {
	q := testQueue(t)
	o := openSpec(t, fmt.Sprintf("POSIXMQ-READ:%s,nonblock,mq-maxmsg=1,mq-msgsize=64", q), xio.ModeRead)
	_, err := o.EffectiveStream().Read(make([]byte, 64))
	if err == nil {
		t.Fatal("nonblock empty Read succeeded")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("nonblock empty Read used a deadline")
	}
}
