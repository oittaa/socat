//go:build linux

package posixmqopen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
	"golang.org/x/sys/unix"
)

var mqSeq atomic.Uint64

func skipIfNoMQ(t *testing.T) {
	t.Helper()
	name := fmt.Sprintf("/socat-mqprobe-%d-%d", os.Getpid(), mqSeq.Add(1))
	fd, err := mqOpen(name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600, nil)
	if err != nil {
		t.Skipf("no POSIX MQ: %v", err)
	}
	_ = mqClose(fd)
	_ = mqUnlink(name)
}

func testQueue(t *testing.T) string {
	t.Helper()
	skipIfNoMQ(t)
	name := fmt.Sprintf("/socat-t-%d-%d", os.Getpid(), mqSeq.Add(1))
	t.Cleanup(func() { _ = mqUnlink(name) })
	return name
}

func testGlobal() *xio.Global {
	return &xio.Global{Log: logx.New(), BlockSize: 8192}
}

func sendMsg(t *testing.T, q, msg string, prio uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel(fmt.Sprintf("POSIXMQ-SEND:%s,mq-prio=%d", q, prio))
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeWrite, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := io.WriteString(o.EffectiveStream(), msg); err != nil {
		t.Fatal(err)
	}
}

func TestMQSyscalls(t *testing.T) {
	q := testQueue(t)
	fd, err := mqOpen(q, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mqClose(fd) }()
	if err := mqTimedSend(fd, []byte("hi"), 1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := mqTimedSend(fd, []byte("lo"), 0, time.Time{}); err != nil {
		t.Fatal(err)
	}
	var attr mqAttr
	if err := mqGetattr(fd, &attr); err != nil {
		t.Fatal(err)
	}
	if attr.Curmsgs != 2 {
		t.Fatalf("curmsgs=%d", attr.Curmsgs)
	}
	buf := make([]byte, attr.Msgsize)
	var prio uint32
	n, err := mqTimedReceive(fd, buf, &prio, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if prio != 1 || string(buf[:n]) != "hi" {
		t.Fatalf("first prio=%d msg=%q", prio, buf[:n])
	}
}

func TestMQTimedSyscallsHonorDeadline(t *testing.T) {
	q := testQueue(t)
	attr := mqAttr{Maxmsg: 1, Msgsize: 16}
	fd, err := mqOpen(q, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600, &attr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mqClose(fd) }()

	if err := mqTimedSend(fd, []byte("full"), 0, time.Time{}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := mqTimedSend(fd, []byte("blocked"), 0, start.Add(40*time.Millisecond)); err != unix.ETIMEDOUT {
		t.Fatalf("timed send error=%v, want %v", err, unix.ETIMEDOUT)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("timed send elapsed %v", elapsed)
	}

	buf := make([]byte, attr.Msgsize)
	if _, err := mqTimedReceive(fd, buf, nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if _, err := mqTimedReceive(fd, buf, nil, start.Add(40*time.Millisecond)); err != unix.ETIMEDOUT {
		t.Fatalf("timed receive error=%v, want %v", err, unix.ETIMEDOUT)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("timed receive elapsed %v", elapsed)
	}
}

func TestPOSIXMQReadPrio(t *testing.T) {
	q := testQueue(t)
	sendMsg(t, q, "low\n", 0)
	sendMsg(t, q, "high\n", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("POSIXMQ-READ:" + q + ",unlink-close")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeRead, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	st := o.EffectiveStream()
	buf := make([]byte, 64)
	n1, err := st.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := st.Read(buf[n1:])
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n1+n2])
	if got != "high\nlow\n" {
		t.Fatalf("got %q", got)
	}
}

func TestPOSIXMQRecvOneshot(t *testing.T) {
	q := testQueue(t)
	sendMsg(t, q, "one", 4)
	sendMsg(t, q, "two", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("POSIXMQ-RECV:" + q)
	if err != nil {
		t.Fatal(err)
	}
	g := testGlobal()
	o, err := xio.OpenChannel(ctx, ch, xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	st := o.EffectiveStream()
	b, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "one" {
		t.Fatalf("oneshot got %q", b)
	}
	if got := g.SessionVars["POSIXMQ_PRIO"]; got != "4" {
		t.Fatalf("POSIXMQ_PRIO=%q", got)
	}
}

func TestPOSIXMQRecvFork(t *testing.T) {
	q := testQueue(t)
	out := filepath.Join(t.TempDir(), "out")

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	left, err := parse.ParseChannel("POSIXMQ-RECV:" + q + ",unlink-early,fork")
	if err != nil {
		t.Fatal(err)
	}
	right, err := parse.ParseChannel("OPEN:" + out + ",creat,append")
	if err != nil {
		t.Fatal(err)
	}
	g := testGlobal()
	g.LeftToRight = true
	errc := make(chan error, 1)
	go func() { errc <- xio.Run(ctx, left, right, g) }()

	// Wait until the queue exists (RECV,unlink-early creates it).
	deadline := time.Now().Add(2 * time.Second)
	for {
		fd, err := mqOpen(q, unix.O_WRONLY, 0, nil)
		if err == nil {
			_ = mqClose(fd)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue not created: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	sendMsg(t, q, "a0\n", 0)
	sendMsg(t, q, "a1\n", 0)

	deadline = time.Now().Add(3 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		got, _ = os.ReadFile(out)
		if bytes.Contains(got, []byte("a0\n")) && bytes.Contains(got, []byte("a1\n")) {
			cancel()
			<-errc
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-errc
	t.Fatalf("got %q", got)
}

func TestPOSIXMQFlush(t *testing.T) {
	q := testQueue(t)
	sendMsg(t, q, "stale", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("POSIXMQ-SEND:" + q + ",mq-flush")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeWrite, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(o.EffectiveStream(), "fresh"); err != nil {
		t.Fatal(err)
	}
	_ = o.Close()

	ch, err = parse.ParseChannel("POSIXMQ-READ:" + q)
	if err != nil {
		t.Fatal(err)
	}
	r, err := xio.OpenChannel(ctx, ch, xio.ModeRead, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	buf := make([]byte, 32)
	n, err := r.EffectiveStream().Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "fresh" {
		t.Fatalf("after flush got %q", buf[:n])
	}
}

func TestPOSIXMQKeywordRDWR(t *testing.T) {
	skipIfNoMQ(t)
	ch, err := parse.ParseChannel("POSIXMQ:/socat-x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenChannel(context.Background(), ch, xio.ModeRDWR, testGlobal())
	if err == nil {
		t.Fatal("expected POSIXMQ bidirectional error")
	}
}

func TestPOSIXMQMaxChildrenRequiresFork(t *testing.T) {
	skipIfNoMQ(t)
	ch, err := parse.ParseChannel("POSIXMQ-RECV:/socat-x,max-children=2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenChannel(context.Background(), ch, xio.ModeRead, testGlobal())
	if err == nil {
		t.Fatal("expected max-children without fork to fail")
	}
}

func TestPOSIXMQSendForkMaxChildren(t *testing.T) {
	q := testQueue(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	qdir := filepath.Join(dir, "q")
	if err := os.Mkdir(qdir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"01", "02", "04"} {
		if err := os.WriteFile(filepath.Join(qdir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	reader, err := parse.ParseChannel("POSIXMQ-READ:" + q + ",unlink-early")
	if err != nil {
		t.Fatal(err)
	}
	writer, err := parse.ParseChannel("OPEN:" + out + ",creat,append")
	if err != nil {
		t.Fatal(err)
	}
	rg := testGlobal()
	rg.LeftToRight = true
	rerr := make(chan error, 1)
	go func() { rerr <- xio.Run(ctx, reader, writer, rg) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		fd, err := mqOpen(q, unix.O_WRONLY, 0, nil)
		if err == nil {
			_ = mqClose(fd)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reader did not create queue: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	sendLeft, err := parse.ParseChannel("POSIXMQ-SEND:" + q + ",fork,max-children=2,interval=0.15")
	if err != nil {
		t.Fatal(err)
	}
	shell := fmt.Sprintf("SHELL:shopt -s nullglob; f=$(ls -1 %s|head -n 1); test -z \"$f\" && exit; { cat %s/$f; rm %s/$f; }; sleep 0.4", qdir, qdir, qdir)
	sendRight, err := parse.ParseChannel(shell)
	if err != nil {
		t.Fatal(err)
	}
	sg := testGlobal()
	sg.RightToLeft = true
	serr := make(chan error, 1)
	sctx, scancel := context.WithCancel(ctx)
	go func() { serr <- xio.Run(sctx, sendLeft, sendRight, sg) }()

	// After two children start, insert message 3 into the output file.
	time.Sleep(400 * time.Millisecond)
	f, err := os.OpenFile(out, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("03\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	deadline = time.Now().Add(4 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		got, _ = os.ReadFile(out)
		if bytes.Contains(got, []byte("01\n")) && bytes.Contains(got, []byte("02\n")) &&
			bytes.Contains(got, []byte("03\n")) && bytes.Contains(got, []byte("04\n")) {
			scancel()
			cancel()
			<-serr
			<-rerr
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	scancel()
	cancel()
	<-serr
	<-rerr
	t.Fatalf("got %q", got)
}

func TestPOSIXMQRecvMaxChildren(t *testing.T) {
	q := testQueue(t)
	out := filepath.Join(t.TempDir(), "out")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	left, err := parse.ParseChannel("POSIXMQ-RECV:" + q + ",unlink-early,fork,max-children=2")
	if err != nil {
		t.Fatal(err)
	}
	// Sleep beyond finishExec's ordinary one-second close grace. max-children
	// must follow the actual child lifetime, not merely relay completion.
	right, err := parse.ParseChannel(`SHELL:cat >>` + out + `; sleep 2`)
	if err != nil {
		t.Fatal(err)
	}
	g := testGlobal()
	g.LeftToRight = true
	g.Linger = 50 * time.Millisecond
	errc := make(chan error, 1)
	go func() { errc <- xio.Run(ctx, left, right, g) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		fd, err := mqOpen(q, unix.O_WRONLY, 0, nil)
		if err == nil {
			_ = mqClose(fd)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue not created: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	sendMsg(t, q, "1\n", 0)
	sendMsg(t, q, "2\n", 0)
	sendMsg(t, q, "4\n", 0)

	// Two children consume 1 and 2 concurrently; 4 stays queued.
	deadline = time.Now().Add(2 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		got, _ = os.ReadFile(out)
		if bytes.Contains(got, []byte("1\n")) && bytes.Contains(got, []byte("2\n")) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !bytes.Contains(got, []byte("1\n")) || !bytes.Contains(got, []byte("2\n")) {
		cancel()
		<-errc
		t.Fatalf("first two messages: %q", got)
	}
	time.Sleep(1300 * time.Millisecond)

	f, err := os.OpenFile(out, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("3\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, _ = os.ReadFile(out)
		if bytes.Contains(got, []byte("3\n")) && bytes.Contains(got, []byte("4\n")) {
			i3 := bytes.Index(got, []byte("3\n"))
			i4 := bytes.Index(got, []byte("4\n"))
			if i3 >= 0 && i4 >= 0 && i3 < i4 {
				cancel()
				<-errc
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-errc
	t.Fatalf("got %q", got)
}

func TestPOSIXMQUnknownAddressNotUsed(t *testing.T) {
	skipIfNoMQ(t)
	ch, err := parse.ParseChannel("POSIXMQ-SEND:::::")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenChannel(context.Background(), ch, xio.ModeWrite, testGlobal())
	if err == nil {
		t.Fatal("expected arity error")
	}
	if bytes.Contains([]byte(err.Error()), []byte("unknown device/address")) {
		t.Fatalf("testaddrs probe must not look unknown: %v", err)
	}
}

func TestPOSIXMQForkHasWrapDial(t *testing.T) {
	skipIfNoMQ(t)
	g := testGlobal()
	ctx := context.Background()

	t.Run("recv", func(t *testing.T) {
		q := testQueue(t)
		spec, err := parse.ParseSpec("POSIXMQ-RECV:" + q + ",unlink-early,fork,readbytes=4")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openPOSIXMQ(ctx, spec, xio.ModeRead, g)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		assertPOSIXMQWrapDialReadbytes(t, o)
	})

	t.Run("send", func(t *testing.T) {
		q := testQueue(t)
		spec, err := parse.ParseSpec("POSIXMQ-SEND:" + q + ",unlink-early,fork,readbytes=4")
		if err != nil {
			t.Fatal(err)
		}
		o, err := openPOSIXMQ(ctx, spec, xio.ModeWrite, g)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		if o.WrapDial == nil {
			t.Fatal("WrapDial is nil")
		}
		assertPOSIXMQWrapDialReadbytes(t, o)
	})
}

func assertPOSIXMQWrapDialReadbytes(t *testing.T, o *xio.Opened) {
	t.Helper()
	if o.WrapDial == nil {
		t.Fatal("WrapDial is nil")
	}
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	st, err := o.WrapDial(a)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = b.Write([]byte("hello"))
		_ = b.Close()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hell" {
		t.Fatalf("readbytes wrap got %q want hell", got)
	}
}

func TestPOSIXMQAppendFcntlOnce(t *testing.T) {
	q := testQueue(t)
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel(fmt.Sprintf("POSIXMQ-SEND:%s,append", q))
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeWrite, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	n := 0
	for _, op := range ops {
		if op == "F_SETFL" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("F_SETFL count=%d want 1 (ops=%v)", n, ops)
	}
}

func TestPOSIXMQEmptyMessageIsEOF(t *testing.T) {
	q := testQueue(t)
	sendMsg(t, q, "", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("POSIXMQ-READ:" + q + ",unlink-close")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeRead, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	n, err := o.EffectiveStream().Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty MQ n=%d err=%v want EOF", n, err)
	}
}

func TestPOSIXMQRecvEmptyOneshotIsEOF(t *testing.T) {
	q := testQueue(t)
	sendMsg(t, q, "", 3)
	sendMsg(t, q, "kept", 0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("POSIXMQ-RECV:" + q)
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, ch, xio.ModeRead, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	b, err := io.ReadAll(o.EffectiveStream())
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("oneshot empty got %q want EOF with no payload", b)
	}
}

func testMQStream(t *testing.T, maxmsg int) (*mqStream, string) {
	t.Helper()
	q := testQueue(t)
	attr := mqAttr{Maxmsg: maxmsg, Msgsize: 16}
	fd, err := mqOpen(q, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600, &attr)
	if err != nil {
		t.Fatal(err)
	}
	s := &mqStream{fd: fd, name: q, msgsize: 16}
	if err := s.attachNotify(); err != nil {
		_ = mqClose(fd)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, q
}

func mqWake(name string) {
	fd, err := mqOpen(name, unix.O_WRONLY, 0, nil)
	if err != nil {
		return
	}
	_ = mqTimedSend(fd, []byte("wake"), 0, time.Now().Add(100*time.Millisecond))
	_ = mqClose(fd)
}

func TestMQStreamCloseUnblocksRead(t *testing.T) {
	s, q := testMQStream(t, 1)
	errc := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 16))
		errc <- err
	}()
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("Close unblocked Read after %v err=%v", elapsed, err)
		}
		if err == nil {
			t.Fatal("blocked Read succeeded after Close")
		}
	case <-time.After(2 * time.Second):
		mqWake(q)
		<-errc
		t.Fatal("Close did not unblock Read")
	}
}

func TestMQStreamSetReadDeadlineUnblocksInFlightRead(t *testing.T) {
	s, q := testMQStream(t, 1)
	errc := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 16))
		errc <- err
	}()
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	if err := s.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("in-flight Read err=%v want deadline exceeded", err)
		}
		if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
			t.Fatalf("SetReadDeadline took %v (deadline snapshot?)", elapsed)
		}
	case <-time.After(2 * time.Second):
		mqWake(q)
		<-errc
		t.Fatal("SetReadDeadline did not unblock in-flight Read")
	}
}

func TestMQStreamSetWriteDeadlineUnblocksInFlightWrite(t *testing.T) {
	s, _ := testMQStream(t, 1)
	if _, err := s.Write([]byte("full")); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("blocked"))
		errc <- err
	}()
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	if err := s.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("in-flight Write err=%v want deadline exceeded", err)
		}
		if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
			t.Fatalf("SetWriteDeadline took %v (deadline snapshot?)", elapsed)
		}
	case <-time.After(2 * time.Second):
		// Drain one message so the blocked send can complete.
		buf := make([]byte, 16)
		_, _ = mqTimedReceive(s.fd, buf, nil, time.Now().Add(100*time.Millisecond))
		<-errc
		t.Fatal("SetWriteDeadline did not unblock in-flight Write")
	}
}

func TestMQStreamNoCloseUnblocksRead(t *testing.T) {
	s, q := testMQStream(t, 1)
	s.noClose = true
	errc := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 16))
		errc <- err
	}()
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("noClose Close unblocked Read after %v err=%v", elapsed, err)
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("noClose in-flight Read err=%v want closed", err)
		}
	case <-time.After(2 * time.Second):
		mqWake(q)
		<-errc
		t.Fatal("noClose Close did not unblock Read")
	}
	if err := mqGetattr(s.fd, &mqAttr{}); err != nil {
		t.Fatalf("noClose Close closed the fd: %v", err)
	}
}
