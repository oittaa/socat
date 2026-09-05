package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

type incomingPacket struct {
	data []byte
	peer netip.AddrPort
}

type connCommand struct {
	kind        byte
	data        []byte
	requestPeer bool
	cancel      <-chan struct{}
	result      chan error
	started     bool
	epoch       uint64
}

// Conn preserves UDP datagram boundaries. Each Write sends one datagram;
// a short Read buffer discards the remainder of that datagram.
type Conn struct {
	mu                          sync.Mutex
	transport                   *packetTransport
	owned                       bool
	session                     *session
	incoming                    chan incomingPacket
	commands                    chan *connCommand
	wake                        chan struct{}
	stop                        chan struct{}
	done                        chan struct{}
	ready                       chan struct{}
	once                        sync.Once
	notify                      chan struct{}
	readQueue                   [][]byte
	readDeadline, writeDeadline time.Time
	state                       tls.ConnectionState
	remote                      netip.AddrPort
	err                         error
	peerEOF, writeClosed        bool
	maxDatagram                 int
	onReady                     func(*Conn) bool
	onClose                     func(*Conn)
	onPeerChanged               func(*Conn, netip.AddrPort)
	packetBudget                *memoryBudget
	sendingApplication          bool
	handshakeCredit             uint64
}

// Client establishes a DTLS 1.3 association. It takes ownership of transport
// after validating the arguments. The context bounds only the handshake.
func Client(ctx context.Context, transport net.PacketConn, peer net.Addr, config *Config) (*Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prepared, err := prepareConfig(config, false)
	if err != nil {
		return nil, err
	}
	address, err := udpAddress(peer)
	if err != nil {
		return nil, err
	}
	if transport == nil {
		return nil, errors.New("dtls: packet transport is required")
	}
	if prepared.AcceptPeer != nil && !prepared.AcceptPeer(address) {
		return nil, errors.New("dtls: peer address rejected")
	}
	c := newConn(address)
	c.owned = true
	c.transport = newPacketTransport(transport, c.deliver, c.fail)
	c.transport.start()
	s, err := newClientSession(prepared, c.sendPacket, time.Now())
	if err != nil {
		c.transport.close(err)
		return nil, err
	}
	c.attach(s)
	go c.run()
	select {
	case <-c.ready:
		return c, nil
	case <-c.done:
		return nil, c.failure()
	case <-ctx.Done():
		c.fail(ctx.Err())
		<-c.done
		return nil, ctx.Err()
	}
}

func newConn(peer netip.AddrPort) *Conn {
	// Buffer a handshake transmission while certificate verification runs.
	return &Conn{incoming: make(chan incomingPacket, flightBurst), commands: make(chan *connCommand),
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		ready: make(chan struct{}), notify: make(chan struct{}), remote: peer}
}

func (c *Conn) attach(s *session) {
	c.session = s
	s.path = &pathState{session: s, peer: packetPath{c.remote, 1}, allowPeer: s.handshake.config.AcceptPeer,
		send: func(to packetPath, data []byte) error {
			return c.transport.write(data, to.remote, time.Time{}, c.stop)
		}, changed: func(to packetPath) {
			c.mu.Lock()
			c.remote = to.remote
			c.signalLocked()
			c.mu.Unlock()
			if c.onPeerChanged != nil {
				c.onPeerChanged(c, to.remote)
			}
		}}
}

func (c *Conn) deliver(data []byte, peer netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil || len(c.incoming) == cap(c.incoming) || !c.packetBudget.reserve(len(data)) {
		return
	}
	select {
	case c.incoming <- incomingPacket{bytes.Clone(data), peer}:
	default:
		c.packetBudget.release(len(data))
	}
}

func (c *Conn) sendPacket(data []byte) error {
	if c.session != nil && !c.session.handshake.client && !c.session.handshake.complete && c.session.handshake.schedule == nil {
		if uint64(len(data)) > c.handshakeCredit {
			return nil
		}
		c.handshakeCredit -= uint64(len(data))
	}
	c.mu.Lock()
	peer, deadline := c.remote, c.writeDeadline
	c.mu.Unlock()
	if !c.sendingApplication {
		deadline = time.Time{}
	}
	return c.transport.write(data, peer, deadline, c.stop)
}

func (c *Conn) signalLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

func (c *Conn) fail(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		close(c.stop)
		c.signalLocked()
		c.mu.Unlock()
	})
}

func (c *Conn) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

func (c *Conn) run() {
	s := c.session
	defer func() {
		c.fail(net.ErrClosed)
		s.reassembly.clear()
		for len(c.incoming) != 0 {
			packet := <-c.incoming
			c.packetBudget.release(len(packet.data))
		}
		if c.owned {
			c.transport.close(net.ErrClosed)
		}
		if c.onClose != nil {
			c.onClose(c)
		}
		close(c.done)
	}()
	var handshakeDeadline time.Time
	if !s.handshake.config.DisableHandshakeTimeout {
		handshakeDeadline = time.Now().Add(s.handshake.config.HandshakeTimeout)
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var pending *connCommand
	ready := false
	for {
		now := time.Now()
		if err := s.tick(now); err != nil {
			c.fail(err)
			return
		}
		if s.handshake.complete && !ready {
			ready = true
			s.wantCIDs = true
			c.publish(nil)
			close(c.ready)
			if c.onReady != nil && !c.onReady(c) {
				return
			}
		}
		if pending != nil {
			select {
			case <-pending.cancel:
				pending = nil
			default:
				if done, err := c.command(pending, now); done {
					pending.result <- err
					pending = nil
				}
			}
		}
		deadline := s.deadline()
		if !ready && !handshakeDeadline.IsZero() && (deadline.IsZero() || handshakeDeadline.Before(deadline)) {
			deadline = handshakeDeadline
		}
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer.Reset(time.Until(deadline))
			timerC = timer.C
		}
		commands := c.commands
		if pending != nil {
			commands = nil
		}
		select {
		case <-c.stop:
			if s.handshake.complete && !c.writeClosed {
				_, _ = s.sendRecordWith(s.currentWriteEpoch(), contentAlert, []byte{1, 0}, s.handshake.peerCID,
					func(data []byte) error { return c.transport.write(data, s.path.peer.remote, time.Time{}, nil) })
			}
			return
		case <-timerC:
			if !ready && !handshakeDeadline.IsZero() && !time.Now().Before(handshakeDeadline) {
				c.fail(context.DeadlineExceeded)
				return
			}
		case <-c.wake:
		case pending = <-commands:
		case packet := <-c.incoming:
			c.packetBudget.release(len(packet.data))
			if !s.handshake.client && !s.handshake.complete && s.handshake.schedule == nil {
				c.handshakeCredit = min(1<<30, c.handshakeCredit+3*uint64(len(packet.data)))
			}
			data, err := s.receiveFrom(packet.data, packetPath{packet.peer, 1}, time.Now())
			if err != nil {
				_, _ = s.sendRecord(s.currentWriteEpoch(), contentAlert, errorAlert(err))
				c.fail(err)
				return
			}
			c.publish(data)
		}
	}
}

func (c *Conn) publish(data [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, packet := range data {
		if len(c.readQueue) < 16 && !c.peerEOF {
			c.readQueue = append(c.readQueue, packet)
		}
	}
	c.peerEOF = c.session.peerClosed != nil
	c.state = c.session.handshake.state
	cidLength := 0
	if c.session.handshake.cidNegotiated {
		cidLength = len(c.session.handshake.peerCID)
	}
	c.maxDatagram = min(maxContent, c.session.handshake.config.MTU-22-cidLength)
	c.signalLocked()
}

func (c *Conn) command(command *connCommand, now time.Time) (bool, error) {
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	if !deadline.IsZero() && !now.Before(deadline) {
		return true, os.ErrDeadlineExceeded
	}
	s := c.session
	var err error
	switch command.kind {
	case contentData:
		if c.writeClosed {
			return true, net.ErrClosed
		}
		c.sendingApplication = true
		err = s.application(command.data)
		c.sendingApplication = false
		if errors.Is(err, errUpdatePending) {
			if e := s.advancePost(now); e != nil {
				return true, e
			}
		}
	case msgKeyUpdate:
		if !command.started {
			command.epoch = s.currentWriteEpoch()
			if s.updating {
				command.epoch++
			}
			err = s.requestKeyUpdate(command.requestPeer, now)
			command.started = err == nil
		}
		if err == nil && s.currentWriteEpoch() <= command.epoch {
			return false, nil
		}
	case msgNewConnectionID:
		if !command.started {
			err = s.provideCIDs(1, true, now)
			command.started = err == nil
		}
		if err == nil && s.post[msgNewConnectionID] != nil {
			return false, nil
		}
	case contentAlert:
		if c.writeClosed {
			return true, nil
		}
		if s.updating || s.updatePending {
			return false, nil
		}
		_, err = s.sendRecord(s.currentWriteEpoch(), contentAlert, []byte{1, 0})
		if err == nil {
			c.writeClosed = true
		}
	default:
		return true, errUnexpectedMessage
	}
	if errors.Is(err, errUpdatePending) || errors.Is(err, errPathPending) {
		return false, nil
	}
	if errors.Is(err, errSequence) {
		c.fail(err)
	}
	return true, err
}

func (c *Conn) execute(command *connCommand) error {
	cancel := make(chan struct{})
	defer func() {
		close(cancel)
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}()
	command.cancel, command.result = cancel, make(chan error, 1)
	var reply <-chan error
	for {
		c.mu.Lock()
		deadline, notify := c.writeDeadline, c.notify
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		commands := c.commands
		if reply != nil {
			commands = nil
		}
		var err error
		done := false
		select {
		case commands <- command:
			reply = command.result
		case err = <-reply:
			done = true
		case <-c.stop:
			err, done = c.failure(), true
		case <-notify:
		case <-timeout:
			err, done = os.ErrDeadlineExceeded, true
		}
		if timer != nil {
			timer.Stop()
		}
		if done {
			return err
		}
	}
}

func (c *Conn) Write(data []byte) (int, error) {
	if len(data) > c.MaxDatagramSize() {
		return 0, errRecordOverflow
	}
	if err := c.execute(&connCommand{kind: contentData, data: bytes.Clone(data)}); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *Conn) Read(data []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		if len(c.readQueue) != 0 {
			packet := c.readQueue[0]
			c.readQueue[0] = nil
			c.readQueue = c.readQueue[1:]
			c.mu.Unlock()
			return copy(data, packet), nil
		}
		if c.peerEOF {
			c.mu.Unlock()
			return 0, io.EOF
		}
		deadline, notify := c.readDeadline, c.notify
		c.mu.Unlock()
		if deadline.IsZero() {
			<-notify
			continue
		}
		if !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-notify:
			timer.Stop()
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *Conn) Close() error {
	c.fail(net.ErrClosed)
	<-c.done
	return nil
}

func (c *Conn) CloseWrite() error { return c.execute(&connCommand{kind: contentAlert}) }

// UpdateKeys waits until the peer acknowledges new sending keys.
func (c *Conn) UpdateKeys(requestPeer bool) error {
	return c.execute(&connCommand{kind: msgKeyUpdate, requestPeer: requestPeer})
}

// RotateConnectionID asks the peer to replace the CID it sends immediately.
func (c *Conn) RotateConnectionID() error {
	return c.execute(&connCommand{kind: msgNewConnectionID})
}

func (c *Conn) LocalAddr() net.Addr { return c.transport.conn.LocalAddr() }

func (c *Conn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return net.UDPAddrFromAddrPort(c.remote)
}

func (c *Conn) ConnectionState() tls.ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// TLSConnectionState exposes authenticated peer metadata to endpoint wrappers.
func (c *Conn) TLSConnectionState() (tls.ConnectionState, bool) {
	state := c.ConnectionState()
	return state, state.HandshakeComplete
}

func (c *Conn) MaxDatagramSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxDatagram
}

func (c *Conn) SetDeadline(t time.Time) error     { return c.setDeadlines(t, t, true, true) }
func (c *Conn) SetReadDeadline(t time.Time) error { return c.setDeadlines(t, time.Time{}, true, false) }
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.setDeadlines(time.Time{}, t, false, true)
}

func (c *Conn) setDeadlines(read, write time.Time, setRead, setWrite bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if setRead {
		c.readDeadline = read
	}
	if setWrite {
		c.writeDeadline = write
	}
	c.signalLocked()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}
