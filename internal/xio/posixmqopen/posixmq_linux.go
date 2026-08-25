//go:build linux

package posixmqopen

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

const mqWaitInterval = 200 * time.Millisecond

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
		n, e := strconv.ParseUint(v, 10, 32)
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
			n, e := strconv.ParseInt(v, 10, 64)
			if e != nil {
				return nil, fmt.Errorf("%s: invalid mq-maxmsg %q", s.Type, v)
			}
			a.Maxmsg = int(n)
		}
		if v := s.OptionValue("mq-msgsize", ""); v != "" {
			n, e := strconv.ParseInt(v, 10, 64)
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

	oneshot := kind == mqRecv
	nonblock := oflag&unix.O_NONBLOCK != 0

	// SEND,fork: connect-style parent loop (interval + max-children).
	if fork && kind == mqSend {
		dial := func(dctx context.Context) (net.Conn, error) {
			if !nonblock {
				if e := waitMQ(dctx, fd, unix.POLLOUT, time.Time{}); e != nil {
					return nil, e
				}
			}
			nfd, e := unix.Dup(fd)
			if e != nil {
				return nil, e
			}
			unix.CloseOnExec(nfd)
			return newMQConn(&mqStream{
				fd:       nfd,
				name:     name,
				prio:     prio,
				msgsize:  msgsize,
				nonblock: nonblock,
			}, name), nil
		}
		wrap := func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommon(s, relay.NetStream{Conn: c})
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
		o := &xio.Opened{
			Kind:        xio.KindListen,
			Listener:    ln,
			MaxChildren: maxChildren,
			Label:       s.Type,
			WrapDial: func(c net.Conn) (relay.Stream, error) {
				return xio.WrapCommon(s, relay.NetStream{Conn: c})
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
	if oneshot {
		if !nonblock {
			if e := waitMQ(ctx, fd, unix.POLLIN, time.Time{}); e != nil {
				cleanup()
				return nil, e
			}
		}
		buf := make([]byte, msgsize)
		var receivedPrio uint32
		n, e := receiveMQ(ctx, fd, buf, &receivedPrio, nonblock, time.Time{})
		if e != nil {
			cleanup()
			return nil, e
		}
		mqs.prio = receivedPrio
		mqs.got = true
		mqs.leftover = append([]byte(nil), buf[:n]...)
		xio.SetSessionEnv(g, "POSIXMQ_PRIO", strconv.FormatUint(uint64(receivedPrio), 10))
	}

	st := relay.Stream(mqs)
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		cleanup()
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

func waitMQ(ctx context.Context, fd int, events int16, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout := int(mqWaitInterval / time.Millisecond)
		if !deadline.IsZero() {
			rem := time.Until(deadline)
			if rem <= 0 {
				return os.ErrDeadlineExceeded
			}
			ms := int(rem / time.Millisecond)
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
		pfd := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(pfd, timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		re := pfd[0].Revents
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

func boundedMQDeadline(deadline time.Time) time.Time {
	bound := time.Now().Add(mqWaitInterval)
	if !deadline.IsZero() && deadline.Before(bound) {
		return deadline
	}
	return bound
}

func retryMQTimedError(err error, deadline time.Time) (bool, error) {
	switch err {
	case unix.EINTR:
		return true, nil
	case unix.ETIMEDOUT:
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return false, os.ErrDeadlineExceeded
		}
		return true, nil
	default:
		return false, err
	}
}

func receiveMQ(ctx context.Context, fd int, buf []byte, prio *uint32, nonblock bool, deadline time.Time) (int, error) {
	if nonblock {
		return mqTimedReceive(fd, buf, prio, time.Time{})
	}
	for {
		if err := waitMQ(ctx, fd, unix.POLLIN, deadline); err != nil {
			return 0, err
		}
		n, err := mqTimedReceive(fd, buf, prio, boundedMQDeadline(deadline))
		if err == nil {
			return n, nil
		}
		if retry, result := retryMQTimedError(err, deadline); !retry {
			return 0, result
		}
	}
}

func sendMQ(ctx context.Context, fd int, msg []byte, prio uint32, nonblock bool, deadline time.Time) error {
	if nonblock {
		return mqTimedSend(fd, msg, prio, time.Time{})
	}
	for {
		if err := waitMQ(ctx, fd, unix.POLLOUT, deadline); err != nil {
			return err
		}
		err := mqTimedSend(fd, msg, prio, boundedMQDeadline(deadline))
		if err == nil {
			return nil
		}
		if retry, result := retryMQTimedError(err, deadline); !retry {
			return result
		}
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
	rdeadline time.Time
	wdeadline time.Time
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
	deadline := s.rdeadline
	nonblock := s.nonblock
	s.mu.Unlock()

	s.mu.Lock()
	if s.rbuf == nil {
		sz := s.msgsize
		if sz < 1 {
			sz = 8192
		}
		s.rbuf = make([]byte, sz)
	}
	buf := s.rbuf
	s.mu.Unlock()

	var prio uint32
	n, err := receiveMQ(context.Background(), s.fd, buf, &prio, nonblock, deadline)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.prio = prio
	s.got = true
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
	deadline := s.wdeadline
	prio := s.prio
	nonblock := s.nonblock
	s.mu.Unlock()
	if err := sendMQ(context.Background(), s.fd, p, prio, nonblock, deadline); err != nil {
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
	s.mu.Unlock()
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
	s.mu.Unlock()
	return nil
}

func (s *mqStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdeadline = t
	s.mu.Unlock()
	return nil
}

func (s *mqStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.wdeadline = t
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
	fd      int
	name    string
	msgsize int
	ctx     context.Context
	mu      sync.Mutex
	closed  bool
}

func (l *mqListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.mu.Unlock()
	buf := make([]byte, l.msgsize)
	var receivedPrio uint32
	n, err := receiveMQ(l.ctx, l.fd, buf, &receivedPrio, false, time.Time{})
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.mu.Unlock()
	conn := newMQConn(&mqStream{
		fd:       l.fd,
		name:     l.name,
		prio:     receivedPrio,
		msgsize:  l.msgsize,
		oneshot:  true,
		noClose:  true,
		got:      true,
		leftover: append([]byte(nil), buf[:n]...),
	}, l.name)
	conn.env = map[string]string{"POSIXMQ_PRIO": strconv.FormatUint(uint64(receivedPrio), 10)}
	return conn, nil
}

func (l *mqListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return mqClose(l.fd)
}

func (l *mqListener) Addr() net.Addr { return mqAddr(l.name) }
