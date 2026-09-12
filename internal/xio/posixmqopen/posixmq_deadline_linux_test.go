//go:build linux

package posixmqopen

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	conn, err := o.Dial()(ctx)
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
		apply(time.Now().Add(2 * time.Second))
		op.mustStayBlocked(t, mqObserve)
		apply(time.Now().Add(-time.Millisecond))
		op.mustTimeout(t, mqObserve)
	case dlClear:
		apply(time.Now().Add(180 * time.Millisecond))
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
