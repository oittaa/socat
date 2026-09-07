package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// ErrHandshakeReadTimeout ends an association after a handshake receive wait expires.
var ErrHandshakeReadTimeout = fmt.Errorf("dtls: handshake receive timeout: %w", os.ErrDeadlineExceeded)

type incomingPacket struct {
	data []byte
	peer netip.AddrPort
}

const (
	maxQueuedRecords    = 256
	maxIncomingBytes    = flightBurst * 65535
	maxApplicationBytes = 16 * maxContent
)

type connCommand struct {
	kind        byte
	data        []byte
	requestPeer bool
	cancel      chan struct{}
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
	incomingBytes, readBytes    int
	readDeadline, writeDeadline time.Time
	state                       tls.ConnectionState
	remote                      netip.AddrPort
	err                         error
	closeNotify                 bool
	peerEOF, writeClosed        bool
	maxDatagram                 int
	onReady                     func(*Conn) bool
	onClose                     func(*Conn)
	onPeerChanged               func(*Conn, netip.AddrPort)
	packetBudget                *memoryBudget
	sendingApplication          *connCommand
	cachedCommand               *connCommand
	handshakeCredit             uint64
	cookieValidated             bool
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
	c.transport.direct = true
	c.transport.configureUnfragmentedProbes(prepared.UnfragmentedProbes)
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
	// Bound bytes separately so small records can arrive in short bursts.
	c := &Conn{incoming: make(chan incomingPacket, maxQueuedRecords), commands: make(chan *connCommand),
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		ready: make(chan struct{}), notify: make(chan struct{}), remote: peer}
	c.cachedCommand = &connCommand{cancel: make(chan struct{}), result: make(chan error, 1)}
	return c
}

func (c *Conn) attach(s *session) {
	c.session = s
	if c.transport != nil {
		s.canProbe = c.transport.unfragmented
	}
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
	if c.err != nil || len(c.incoming) == cap(c.incoming) || len(data) > maxIncomingBytes-c.incomingBytes || !c.packetBudget.reserve(len(data)) {
		return
	}
	select {
	case c.incoming <- incomingPacket{bytes.Clone(data), peer}:
		c.incomingBytes += len(data)
	default:
		c.packetBudget.release(len(data))
	}
}

func (c *Conn) releasePacket(size int) {
	c.mu.Lock()
	c.incomingBytes -= size
	c.mu.Unlock()
	c.packetBudget.release(size)
}

func (c *Conn) sendPacket(data []byte) error {
	if c.session != nil && !c.cookieValidated && !c.session.handshake.client && !c.session.handshake.complete && c.session.handshake.schedule == nil {
		if uint64(len(data)) > c.handshakeCredit {
			return nil
		}
		c.handshakeCredit -= uint64(len(data))
	}
	c.mu.Lock()
	peer, deadline := c.remote, c.writeDeadline
	c.mu.Unlock()
	if command := c.sendingApplication; command != nil {
		return c.transport.writeApplication(data, peer, deadline, c.stop, command.cancel)
	}
	return c.transport.write(data, peer, time.Time{}, c.stop)
}

func (c *Conn) signalLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

func (c *Conn) signalWake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Conn) fail(err error) {
	c.shutdown(err, false)
}

func (c *Conn) shutdown(err error, notify bool) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.closeNotify = notify
		if c.transport != nil {
			c.transport.cancelWrite(c.stop)
		} else {
			close(c.stop)
		}
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
	abort := false
	defer func() {
		c.fail(net.ErrClosed)
		// Close may interrupt a control write before the stop case runs.
		if c.closeNotify && !abort && s.handshake.complete && !c.writeClosed {
			_, _ = s.sendRecordWith(s.currentWriteEpoch(), contentAlert, []byte{1, 0}, s.handshake.peerCID,
				func(data []byte) error { return c.transport.write(data, s.path.peer.remote, time.Time{}, nil) })
		}
		s.reassembly.clear()
		for len(c.incoming) != 0 {
			packet := <-c.incoming
			c.releasePacket(len(packet.data))
		}
		if c.owned {
			c.transport.close(net.ErrClosed)
		}
		if c.onClose != nil {
			c.onClose(c)
		}
		close(c.done)
	}()
	started := time.Now()
	select {
	case <-c.stop:
		return
	default:
	}
	if err := s.processHandshakes(started); err != nil {
		abort = true
		_, _ = s.sendRecord(s.currentWriteEpoch(), contentAlert, errorAlert(err))
		c.fail(err)
		return
	}
	var handshakeDeadline time.Time
	if !s.handshake.config.DisableHandshakeTimeout {
		handshakeDeadline = started.Add(s.handshake.config.HandshakeTimeout)
	}
	ready := false
	receivePacket := func(packet incomingPacket) bool {
		c.releasePacket(len(packet.data))
		select {
		case <-c.stop:
			return false
		default:
		}
		if !ready && !handshakeDeadline.IsZero() && !time.Now().Before(handshakeDeadline) {
			c.fail(context.DeadlineExceeded)
			return false
		}
		if !s.handshake.client && !s.handshake.complete && s.handshake.schedule == nil {
			c.handshakeCredit = min(1<<30, c.handshakeCredit+3*uint64(len(packet.data)))
		}
		data, err := s.receiveFrom(packet.data, packetPath{packet.peer, 1}, time.Now())
		if err != nil {
			abort = !errors.Is(err, net.ErrClosed)
			if abort {
				_, _ = s.sendRecord(s.currentWriteEpoch(), contentAlert, errorAlert(err))
			}
			c.fail(err)
			return false
		}
		c.publish(data)
		return true
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var pending *connCommand
	queuedBeforeTimeout := -1
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		now := time.Now()
		waitDeadline := time.Time{}
		if !ready {
			// HandshakeTimeout stays active until the final flight is sent.
			waitDeadline = handshakeDeadline
			if !handshakeDeadline.IsZero() && !now.Before(handshakeDeadline) {
				c.fail(context.DeadlineExceeded)
				return
			}
		}
		if !s.handshake.complete {
			if timeout := s.handshake.config.HandshakeReadTimeout; timeout > 0 {
				lastReceive := s.handshakeReceived
				if lastReceive.IsZero() {
					lastReceive = started
				}
				deadline := lastReceive.Add(timeout)
				if !now.Before(deadline) {
					// Give the existing queue one chance; new junk cannot prolong expiry.
					if queuedBeforeTimeout < 0 {
						queuedBeforeTimeout = len(c.incoming)
					}
					if queuedBeforeTimeout == 0 {
						c.fail(ErrHandshakeReadTimeout)
						return
					}
					packet := <-c.incoming
					queuedBeforeTimeout--
					if !receivePacket(packet) {
						return
					}
					if s.handshakeReceived.After(lastReceive) {
						queuedBeforeTimeout = -1
					}
					continue
				}
				if waitDeadline.IsZero() || deadline.Before(waitDeadline) {
					waitDeadline = deadline
				}
			}
		}
		queuedBeforeTimeout = -1
		if err := s.tick(now); err != nil {
			abort = !errors.Is(err, net.ErrClosed)
			c.fail(err)
			return
		}
		c.publishMaxDatagram()
		if s.handshake.complete && s.handshakeFlightSent() && !ready {
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
					result := pending.result
					pending = nil
					result <- err
				}
			}
		}
		deadline := s.deadline()
		if !ready && !waitDeadline.IsZero() && (deadline.IsZero() || waitDeadline.Before(deadline)) {
			deadline = waitDeadline
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
			return
		case <-timerC:
		case <-c.wake:
		case pending = <-commands:
		case packet := <-c.incoming:
			if !receivePacket(packet) {
				return
			}
		}
	}
}

func (c *Conn) publish(data [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wasEmpty := len(c.readQueue) == 0
	queued := false
	for _, packet := range data {
		if len(c.readQueue) < maxQueuedRecords && cap(packet) <= maxApplicationBytes-c.readBytes && !c.peerEOF {
			// Decryption transfers ownership; charge retained padding and capacity too.
			c.readQueue = append(c.readQueue, packet)
			c.readBytes += cap(packet)
			queued = true
		}
	}
	eof := c.session.peerClosed != nil
	changed := queued && wasEmpty || eof != c.peerEOF
	c.peerEOF = eof
	c.state = c.session.handshake.state
	c.maxDatagram = c.datagramBudget()
	if changed {
		c.signalLocked()
	}
}

func (c *Conn) datagramBudget() int {
	cidLength := 0
	if c.session.handshake.cidNegotiated {
		cidLength = len(c.session.handshake.peerCID)
	}
	n := min(maxContent, c.session.effectiveMTU()-datagramOverhead(cidLength, defaultAEADTag))
	if n < 0 {
		return 0
	}
	return n
}

func (c *Conn) publishMaxDatagram() {
	n := c.datagramBudget()
	c.mu.Lock()
	c.maxDatagram = n
	c.mu.Unlock()
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
		c.sendingApplication = command
		err = s.application(command.data)
		c.sendingApplication = nil
		if isMessageTooLong(err) {
			c.publishMaxDatagram()
		}
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
	if errors.Is(err, errWritePending) {
		c.signalWake()
		return false, nil
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
	if command.cancel == nil {
		command.cancel = make(chan struct{})
	}
	if command.result == nil {
		command.result = make(chan error, 1)
	}
	reusable := false
	defer func() {
		if reusable {
			// The consumed successful reply returns ownership to the caller.
			command.data = nil
			c.mu.Lock()
			if c.cachedCommand == nil {
				c.cachedCommand = command
			}
			c.mu.Unlock()
		} else {
			c.transport.cancelWrite(command.cancel)
		}
		c.signalWake()
	}()
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
			reusable = err == nil && command.kind == contentData
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
	c.mu.Lock()
	if len(data) > c.maxDatagram {
		c.mu.Unlock()
		return 0, errRecordOverflow
	}
	command := c.cachedCommand
	c.cachedCommand = nil
	c.mu.Unlock()
	if command == nil {
		command = &connCommand{}
	}
	// A deadline can return before the session finishes encoding this command.
	*command = connCommand{kind: contentData, data: bytes.Clone(data), cancel: command.cancel, result: command.result}
	if err := c.execute(command); err != nil {
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
			c.readBytes -= cap(packet)
			c.readQueue[0] = nil
			if len(c.readQueue) == 1 {
				c.readQueue = c.readQueue[:0]
			} else {
				c.readQueue = c.readQueue[1:]
			}
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
	c.shutdown(net.ErrClosed, true)
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
	c.signalWake()
	return nil
}
