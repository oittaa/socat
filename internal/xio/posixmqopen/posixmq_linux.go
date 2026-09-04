//go:build linux

package posixmqopen

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

const mqWaitInterval = 200 * time.Millisecond

// mqTryOnce is an already-expired absolute timeout: mq_timed* returns
// immediately, taking a message or slot if one is already available.
var mqTryOnce = time.Unix(0, 1)

func init() {
	xio.FeaturePOSIXMQ = true
}

func openPOSIXMQ(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	name, err := queueName(s)
	if err != nil {
		return nil, err
	}
	kind := kindOf(s.Type)
	if kind == mqBidir && mode == xio.ModeRDWR && s.Type == "POSIXMQ" {
		return nil, fmt.Errorf("keyword \"POSIXMQ\" in bidirectional mode might unwanted flush the queue; use \"POSIXMQ-BIDIRECTIONAL\" to confirm usage")
	}

	fork, maxChildren, err := xio.ForkLimits(s)
	if err != nil {
		return nil, err
	}

	prio := uint32(0)
	if v := s.OptionValue("mq-prio", ""); v != "" {
		n, e := strconv.ParseUint(v, 0, 32)
		if e != nil {
			return nil, fmt.Errorf("%s: invalid mq-prio %q", s.Type, v)
		}
		prio = uint32(n)
	}

	oflag := 0
	optCreat := true
	if s.HasOption("creat") {
		optCreat = s.BoolOption("creat")
	}
	if optCreat {
		oflag |= unix.O_CREAT
	}
	if s.BoolOption("excl") {
		oflag |= unix.O_EXCL
	}
	if s.HasOption("nonblock") && s.BoolOption("nonblock") {
		oflag |= unix.O_NONBLOCK
	}
	switch kind {
	case mqRead, mqRecv:
		oflag |= unix.O_RDONLY
	case mqSend:
		oflag |= unix.O_WRONLY
	default:
		switch mode {
		case xio.ModeRead:
			oflag |= unix.O_RDONLY
		case xio.ModeWrite:
			oflag |= unix.O_WRONLY
		default:
			oflag |= unix.O_RDWR
		}
	}

	modePerm, err := xio.ParseUnixMode(s, uint32(xio.DefaultCreateMode))
	if err != nil {
		return nil, err
	}

	var attr *mqAttr
	if s.HasOption("mq-maxmsg") || s.HasOption("mq-msgsize") {
		a := mqAttr{}
		if v := s.OptionValue("mq-maxmsg", ""); v != "" {
			n, e := strconv.ParseInt(v, 0, 64)
			if e != nil {
				return nil, fmt.Errorf("%s: invalid mq-maxmsg %q", s.Type, v)
			}
			a.Maxmsg = int(n)
		}
		if v := s.OptionValue("mq-msgsize", ""); v != "" {
			n, e := strconv.ParseInt(v, 0, 64)
			if e != nil {
				return nil, fmt.Errorf("%s: invalid mq-msgsize %q", s.Type, v)
			}
			a.Msgsize = int(n)
		}
		if a.Maxmsg == 0 {
			if n, ok := readProcLong("/proc/sys/fs/mqueue/msg_default"); ok {
				a.Maxmsg = int(n)
			} else {
				a.Maxmsg = 10
			}
		}
		if a.Msgsize == 0 {
			if n, ok := readProcLong("/proc/sys/fs/mqueue/msgsize_default"); ok {
				a.Msgsize = int(n)
			} else {
				a.Msgsize = 8192
			}
		}
		attr = &a
	}

	if s.BoolOption("unlink-early") {
		if e := mqUnlink(name); e != nil && e != unix.ENOENT {
			if g != nil && g.Log != nil {
				g.Log.Infof("mq_unlink(%q): %s", name, e)
			}
		}
	}
	if s.BoolOption("mq-flush") {
		if e := flushQueue(name); e != nil {
			return nil, e
		}
	}

	var fd int
	err = xio.WithUmask(s, func() error {
		return xio.WithRetry(ctx, s, g, "mq_open", func() error {
			var e error
			fd, e = mqOpen(name, oflag, modePerm, attr)
			if e != nil {
				return fmt.Errorf("mq_open(%q, %#o, %#o): %w", name, oflag, modePerm, e)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)

	got := mqAttr{}
	if e := mqGetattr(fd, &got); e != nil {
		_ = mqClose(fd)
		return nil, fmt.Errorf("mq_getattr(%d): %w", fd, e)
	}
	msgsize := got.Msgsize
	if msgsize < 1 {
		msgsize = 8192
	}
	if g != nil && g.Log != nil {
		g.Log.Infof("POSIXMQ queue %q attrs: { flags=%d, maxmsg=%d, msgsize=%d, curmsgs=%d }",
			name, got.Flags, got.Maxmsg, got.Msgsize, got.Curmsgs)
	}

	unlinkClose := s.BoolOption("unlink-close")
	unregister := func() {}
	cleanup := func() {
		unregister()
		_ = mqClose(fd)
		if unlinkClose {
			_ = mqUnlink(name)
		}
	}
	if unlinkClose {
		n := name
		unregister = xio.RegisterExitHook(func() { _ = mqUnlink(n) })
	}

	// perm= is mq_open mode. Apply remaining lifecycle options on the mqd
	// before wrapping or fork sessions so they are not dropped on mqStream.
	if err := xio.ApplyFDLifecycleOnFD(fd, s); err != nil {
		cleanup()
		return nil, err
	}

	oneshot := kind == mqRecv
	nonblock := oflag&unix.O_NONBLOCK != 0

	// SEND,fork: connect-style parent loop (interval + max-children).
	if fork && kind == mqSend {
		dial := func(dctx context.Context) (net.Conn, error) {
			if !nonblock {
				if e := waitMQ(dctx, fd, unix.POLLOUT, -1, nil); e != nil {
					return nil, e
				}
			}
			nfd, e := dupCLOEXEC(fd)
			if e != nil {
				return nil, e
			}
			st := &mqStream{
				fd:       nfd,
				name:     name,
				prio:     prio,
				msgsize:  msgsize,
				nonblock: nonblock,
			}
			if e := st.attachNotify(); e != nil {
				_ = unix.Close(nfd)
				return nil, e
			}
			return newMQConn(st, name), nil
		}
		wrap := func(c net.Conn) (relay.Stream, error) {
			return xio.SetupStream(s, relay.NetStream{Conn: c})
		}
		o := &xio.Opened{
			Kind:        xio.KindDial,
			MaxChildren: maxChildren,
			Interval:    xio.ParseRetry(s).Interval,
			Label:       s.Type,
			Dial:        dial,
			WrapDial:    wrap,
		}
		o.AddCleanup(cleanup)
		return o, nil
	}

	// RECV,fork: one child per queued message.
	if fork && oneshot {
		ln := &mqListener{
			fd:      fd,
			name:    name,
			msgsize: msgsize,
			ctx:     ctx,
		}
		if e := ln.attachNotify(); e != nil {
			cleanup()
			return nil, e
		}
		o := &xio.Opened{
			Kind:        xio.KindListen,
			Listener:    ln,
			MaxChildren: maxChildren,
			Label:       s.Type,
			WrapDial: func(c net.Conn) (relay.Stream, error) {
				return xio.SetupStream(s, relay.NetStream{Conn: c})
			},
		}
		o.AddCleanup(func() {
			unregister()
			_ = ln.Close()
			if unlinkClose {
				_ = mqUnlink(name)
			}
		})
		return o, nil
	}

	mqs := &mqStream{
		fd:       fd,
		name:     name,
		prio:     prio,
		msgsize:  msgsize,
		oneshot:  oneshot,
		nonblock: nonblock,
	}
	if e := mqs.attachNotify(); e != nil {
		cleanup()
		return nil, e
	}
	if oneshot {
		if !nonblock {
			if e := waitMQ(ctx, fd, unix.POLLIN, -1, nil); e != nil {
				mqs.releaseNotify()
				cleanup()
				return nil, e
			}
		}
		buf := make([]byte, msgsize)
		var receivedPrio uint32
		n, e := receiveMQ(ctx, fd, buf, &receivedPrio, nonblock, -1, nil)
		if e != nil {
			mqs.releaseNotify()
			cleanup()
			return nil, e
		}
		mqs.prio = receivedPrio
		mqs.got = true
		mqs.leftover = append([]byte(nil), buf[:n]...)
		xio.SetSessionEnv(g, "POSIXMQ_PRIO", strconv.FormatUint(uint64(receivedPrio), 10))
	}

	st := relay.Stream(mqs)
	st, err = xio.SetupStream(s, st)
	if err != nil {
		_ = mqs.Close()
		unregister()
		if unlinkClose {
			_ = mqUnlink(name)
		}
		return nil, err
	}
	o := &xio.Opened{Stream: st, Label: s.Type}
	o.AddCleanup(func() {
		unregister()
		if unlinkClose {
			_ = mqUnlink(name)
		}
	})
	return o, nil
}

func flushQueue(name string) error {
	fd, err := mqOpen(name, unix.O_RDONLY|unix.O_NONBLOCK, 0, nil)
	if err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("mq_open(%q) flush: %w", name, err)
	}
	defer func() { _ = mqClose(fd) }()
	var attr mqAttr
	if err := mqGetattr(fd, &attr); err != nil {
		return fmt.Errorf("mq_getattr flush: %w", err)
	}
	if attr.Curmsgs == 0 {
		return nil
	}
	bufsiz := attr.Msgsize
	if bufsiz < 1 {
		bufsiz = 8192
	}
	buf := make([]byte, bufsiz)
	for {
		_, err := mqTimedReceive(fd, buf, nil, time.Time{})
		if err != nil {
			if err == unix.EAGAIN {
				return nil
			}
			return fmt.Errorf("mq_receive flush: %w", err)
		}
	}
}

type mqNotify struct {
	mu sync.Mutex
	fd int
}

func newMQNotify() (*mqNotify, error) {
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return &mqNotify{fd: fd}, nil
}

func (n *mqNotify) pollFD() int {
	if n == nil {
		return -1
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fd
}

func (n *mqNotify) wake() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fd < 0 {
		return
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 1)
	_, _ = unix.Write(n.fd, buf[:])
}

func (n *mqNotify) close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	fd := n.fd
	n.fd = -1
	n.mu.Unlock()
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func drainNotify(fd int) {
	if fd < 0 {
		return
	}
	var buf [8]byte
	for {
		_, err := unix.Read(fd, buf[:])
		if err != nil {
			return
		}
	}
}

func mqLiveErr(live func() (closed bool, dl time.Time)) error {
	if live == nil {
		return nil
	}
	closed, dl := live()
	if closed {
		return net.ErrClosed
	}
	if !dl.IsZero() && time.Until(dl) <= 0 {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func mqClosed(live func() (closed bool, dl time.Time)) bool {
	if live == nil {
		return false
	}
	closed, _ := live()
	return closed
}

func dupCLOEXEC(fd int) (int, error) {
	n, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if n < 0 {
		return -1, unix.EBADF
	}
	return n, nil
}

// mqWaitHook is an optional test hook fired just before each poll.
type mqWaitHook func()

var mqWaitEntered atomic.Pointer[mqWaitHook]

func waitMQ(ctx context.Context, fd int, events int16, notifyFD int, live func() (closed bool, dl time.Time)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := mqLiveErr(live); err != nil {
			return err
		}
		var dl time.Time
		if live != nil {
			_, dl = live()
		}
		// Never wait indefinitely: a shared eventfd wake can be observed by
		// only one poller. Bounded waits recheck close and deadline state.
		timeout := int(mqWaitInterval / time.Millisecond)
		if timeout < 1 {
			timeout = 1
		}
		if !dl.IsZero() {
			rem := time.Until(dl)
			if rem <= 0 {
				return os.ErrDeadlineExceeded
			}
			ms := int((rem + time.Millisecond - 1) / time.Millisecond)
			if ms < 1 {
				ms = 1
			}
			if ms < timeout {
				timeout = ms
			}
		}
		if fd < 0 || fd > math.MaxInt32 {
			return unix.EBADF
		}
		if h := mqWaitEntered.Load(); h != nil {
			(*h)()
		}
		pfds := []unix.PollFd{{Fd: int32(fd), Events: events}}
		notifyIdx := -1
		if notifyFD >= 0 && notifyFD <= math.MaxInt32 {
			notifyIdx = len(pfds)
			pfds = append(pfds, unix.PollFd{Fd: int32(notifyFD), Events: unix.POLLIN})
		}
		n, err := unix.Poll(pfds, timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		// Recheck before acting on queue readiness. Poll can return both
		// POLLIN/POLLOUT and a deadline/close wake at once.
		if err := mqLiveErr(live); err != nil {
			return err
		}
		if notifyIdx >= 0 {
			re := pfds[notifyIdx].Revents
			if re&(unix.POLLIN|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				// Leave a close signal readable so every waiter observes it.
				if !mqClosed(live) {
					drainNotify(notifyFD)
				}
			}
		}
		if n == 0 {
			continue
		}
		re := pfds[0].Revents
		if re&unix.POLLNVAL != 0 {
			return unix.EBADF
		}
		if re&events != 0 {
			return nil
		}
		if re&(unix.POLLERR|unix.POLLHUP) != 0 {
			return io.EOF
		}
	}
}

func receiveMQ(ctx context.Context, fd int, buf []byte, prio *uint32, nonblock bool, notifyFD int, live func() (closed bool, dl time.Time)) (int, error) {
	if nonblock {
		return mqTimedReceive(fd, buf, prio, time.Time{})
	}
	for {
		if err := mqLiveErr(live); err != nil {
			return 0, err
		}
		if err := waitMQ(ctx, fd, unix.POLLIN, notifyFD, live); err != nil {
			return 0, err
		}
		if err := mqLiveErr(live); err != nil {
			return 0, err
		}
		n, err := mqTimedReceive(fd, buf, prio, mqTryOnce)
		if err == nil {
			if live != nil {
				if closed, _ := live(); closed {
					return 0, net.ErrClosed
				}
			}
			return n, nil
		}
		if err == unix.EINTR || err == unix.ETIMEDOUT || err == unix.EAGAIN {
			continue
		}
		return 0, err
	}
}

func sendMQ(ctx context.Context, fd int, msg []byte, prio uint32, nonblock bool, notifyFD int, live func() (closed bool, dl time.Time)) error {
	if nonblock {
		return mqTimedSend(fd, msg, prio, time.Time{})
	}
	for {
		if err := mqLiveErr(live); err != nil {
			return err
		}
		if err := waitMQ(ctx, fd, unix.POLLOUT, notifyFD, live); err != nil {
			return err
		}
		if err := mqLiveErr(live); err != nil {
			return err
		}
		err := mqTimedSend(fd, msg, prio, mqTryOnce)
		if err == nil {
			if live != nil {
				if closed, _ := live(); closed {
					return net.ErrClosed
				}
			}
			return nil
		}
		if err == unix.EINTR || err == unix.ETIMEDOUT || err == unix.EAGAIN {
			continue
		}
		return err
	}
}

type mqStream struct {
	fd       int
	name     string
	prio     uint32
	msgsize  int
	oneshot  bool
	noClose  bool
	nonblock bool

	mu        sync.Mutex
	got       bool
	leftover  []byte
	rbuf      []byte
	closed    bool
	inflight  int
	notify    *mqNotify
	rdeadline time.Time
	wdeadline time.Time
}

func (s *mqStream) attachNotify() error {
	n, err := newMQNotify()
	if err != nil {
		return err
	}
	s.notify = n
	return nil
}

func (s *mqStream) releaseNotify() {
	s.mu.Lock()
	n := s.notify
	s.notify = nil
	s.mu.Unlock()
	n.close()
}

func (s *mqStream) live(read bool) func() (closed bool, dl time.Time) {
	return func() (bool, time.Time) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if read {
			return s.closed, s.rdeadline
		}
		return s.closed, s.wdeadline
	}
}

func (s *mqStream) beginOp() (fd int, notifyFD int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.fd < 0 {
		return -1, -1, net.ErrClosed
	}
	fd, err = dupCLOEXEC(s.fd)
	if err != nil {
		return -1, -1, err
	}
	s.inflight++
	return fd, s.notify.pollFD(), nil
}

func (s *mqStream) endOp(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	s.mu.Lock()
	s.inflight--
	var n *mqNotify
	if s.closed && s.inflight == 0 {
		n = s.notify
		s.notify = nil
	}
	s.mu.Unlock()
	n.close()
}

func (s *mqStream) wakeLocked() {
	if s.notify != nil {
		s.notify.wake()
	}
}

func (s *mqStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if len(s.leftover) > 0 {
		n := copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		s.mu.Unlock()
		return n, nil
	}
	if s.oneshot && s.got {
		s.mu.Unlock()
		return 0, io.EOF
	}
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		s.mu.Unlock()
		return 0, nil
	}
	if s.rbuf == nil {
		sz := s.msgsize
		if sz < 1 {
			sz = 8192
		}
		s.rbuf = make([]byte, sz)
	}
	buf := s.rbuf
	nonblock := s.nonblock
	s.mu.Unlock()

	fd, notifyFD, err := s.beginOp()
	if err != nil {
		return 0, err
	}
	defer s.endOp(fd)

	var prio uint32
	n, err := receiveMQ(context.Background(), fd, buf, &prio, nonblock, notifyFD, s.live(true))
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.prio = prio
	s.got = true
	if n == 0 {
		s.mu.Unlock()
		return 0, io.EOF
	}
	m := copy(p, buf[:n])
	if m < n {
		s.leftover = append([]byte(nil), buf[m:n]...)
	}
	s.mu.Unlock()
	return m, nil
}

func (s *mqStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	prio := s.prio
	nonblock := s.nonblock
	s.mu.Unlock()

	fd, notifyFD, err := s.beginOp()
	if err != nil {
		return 0, err
	}
	defer s.endOp(fd)

	if err := sendMQ(context.Background(), fd, p, prio, nonblock, notifyFD, s.live(false)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *mqStream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	noClose := s.noClose
	fd := s.fd
	if !noClose {
		s.fd = -1
	}
	s.wakeLocked()
	n := s.notify
	inflight := s.inflight
	if inflight == 0 {
		s.notify = nil
	}
	s.mu.Unlock()
	if inflight == 0 {
		n.close()
	}
	if noClose {
		return nil
	}
	return mqClose(fd)
}

func (s *mqStream) ShutdownWrite() error { return nil }

func (s *mqStream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdeadline = t
	s.wdeadline = t
	s.wakeLocked()
	s.mu.Unlock()
	return nil
}

func (s *mqStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdeadline = t
	s.wakeLocked()
	s.mu.Unlock()
	return nil
}

func (s *mqStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.wdeadline = t
	s.wakeLocked()
	s.mu.Unlock()
	return nil
}

type mqAddr string

func (a mqAddr) Network() string { return "posixmq" }
func (a mqAddr) String() string  { return string(a) }

type mqConn struct {
	*mqStream
	local  net.Addr
	remote net.Addr
	env    map[string]string
}

func newMQConn(s *mqStream, name string) *mqConn {
	a := mqAddr(name)
	return &mqConn{mqStream: s, local: a, remote: a}
}

func (c *mqConn) LocalAddr() net.Addr                   { return c.local }
func (c *mqConn) RemoteAddr() net.Addr                  { return c.remote }
func (c *mqConn) SessionEnvironment() map[string]string { return c.env }

type mqListener struct {
	fd       int
	name     string
	msgsize  int
	ctx      context.Context
	mu       sync.Mutex
	closed   bool
	inflight int
	notify   *mqNotify
}

func (l *mqListener) attachNotify() error {
	n, err := newMQNotify()
	if err != nil {
		return err
	}
	l.notify = n
	return nil
}

func (l *mqListener) live() func() (closed bool, dl time.Time) {
	return func() (bool, time.Time) {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.closed, time.Time{}
	}
}

func (l *mqListener) beginOp() (fd int, notifyFD int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.fd < 0 {
		return -1, -1, net.ErrClosed
	}
	fd, err = dupCLOEXEC(l.fd)
	if err != nil {
		return -1, -1, err
	}
	l.inflight++
	return fd, l.notify.pollFD(), nil
}

func (l *mqListener) endOp(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	l.mu.Lock()
	l.inflight--
	var n *mqNotify
	if l.closed && l.inflight == 0 {
		n = l.notify
		l.notify = nil
	}
	l.mu.Unlock()
	n.close()
}

func (l *mqListener) Accept() (net.Conn, error) {
	fd, notifyFD, err := l.beginOp()
	if err != nil {
		return nil, err
	}
	defer l.endOp(fd)

	buf := make([]byte, l.msgsize)
	var receivedPrio uint32
	n, err := receiveMQ(l.ctx, fd, buf, &receivedPrio, false, notifyFD, l.live())
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	name := l.name
	msgsize := l.msgsize
	shared := l.fd
	l.mu.Unlock()
	child := &mqStream{
		fd:       shared,
		name:     name,
		prio:     receivedPrio,
		msgsize:  msgsize,
		oneshot:  true,
		noClose:  true,
		got:      true,
		leftover: append([]byte(nil), buf[:n]...),
	}
	if e := child.attachNotify(); e != nil {
		return nil, e
	}
	conn := newMQConn(child, name)
	conn.env = map[string]string{"POSIXMQ_PRIO": strconv.FormatUint(uint64(receivedPrio), 10)}
	return conn, nil
}

func (l *mqListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	fd := l.fd
	l.fd = -1
	if l.notify != nil {
		l.notify.wake()
	}
	n := l.notify
	inflight := l.inflight
	if inflight == 0 {
		l.notify = nil
	}
	l.mu.Unlock()
	if inflight == 0 {
		n.close()
	}
	return mqClose(fd)
}

func (l *mqListener) Addr() net.Addr { return mqAddr(l.name) }
