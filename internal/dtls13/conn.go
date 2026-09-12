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

type commandKind uint8

const (
	commandWrite commandKind = iota + 1
	commandCloseWrite
	commandUpdateKeys
	commandRotateCID
)

type connCommand struct {
	kind        commandKind
	data        []byte
	requestPeer bool
	cancel      chan struct{}
	result      chan error
	started     bool
	epoch       uint64
}

// connConfig is set-once wiring. Pointers and channels are not replaced.
type connConfig struct {
	transport     *packetTransport
	owned         bool
	onReady       func(*Conn) bool
	onClose       func(*Conn)
	onPeerChanged func(*Conn, netip.AddrPort)
	packetBudget  *memoryBudget
	incoming      chan incomingPacket
	commands      chan *connCommand
	wake          chan struct{}
	stop          chan struct{}
	done          chan struct{}
	ready         chan struct{}
}

// connShared is guarded by mu. The driver publishes; Read, Write, Close,
// and deadlines observe.
type connShared struct {
	mu                          sync.Mutex
	once                        sync.Once
	notify                      chan struct{}
	readQueue                   [][]byte
	incomingBytes, readBytes    int
	readDeadline, writeDeadline time.Time
	state                       tls.ConnectionState
	remote                      netip.AddrPort
	err                         error
	closeNotify                 bool
	peerEOF                     bool
	maxDatagram                 int
	cachedCommand               *connCommand
}

// connDriver is the run-owned protocol engine. It owns the session,
// handshake timing, readiness, commands, and teardown. Other goroutines
// use Conn commands and published snapshots instead of this state.
type connDriver struct {
	conn *Conn

	session            *session
	sendingApplication *connCommand
	pending            *connCommand
	handshakeCredit    uint64
	cookieValidated    bool
	writeClosed        bool

	started             time.Time
	handshakeDeadline   time.Time
	ready               bool
	abort               bool
	queuedBeforeTimeout int
}

// Conn preserves UDP datagram boundaries. Each Write sends one datagram;
// a short Read buffer discards the remainder of that datagram.
type Conn struct {
	config connConfig
	shared connShared
	driver *connDriver
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
	c.config.owned = true
	c.config.transport = newPacketTransport(transport, c.deliver, c.fail)
	c.config.transport.direct = true
	c.config.transport.start()
	// newClientSession sends the ClientHello; transport and driver.sendPacket
	// are already wired so that path does not depend on an attached session.
	s, err := newClientSession(prepared, c.driver.sendPacket, time.Now())
	if err != nil {
		c.config.transport.close(err)
		return nil, err
	}
	c.driver.attach(s)
	go c.driver.run()
	select {
	case <-c.config.ready:
		return c, nil
	case <-c.config.done:
		return nil, c.failure()
	case <-ctx.Done():
		c.fail(ctx.Err())
		<-c.config.done
		return nil, ctx.Err()
	}
}

func newConn(peer netip.AddrPort) *Conn {
	// Bound bytes separately so small records can arrive in short bursts.
	c := &Conn{
		config: connConfig{
			incoming: make(chan incomingPacket, maxQueuedRecords),
			commands: make(chan *connCommand),
			wake:     make(chan struct{}, 1),
			stop:     make(chan struct{}),
			done:     make(chan struct{}),
			ready:    make(chan struct{}),
		},
		shared: connShared{
			notify:        make(chan struct{}),
			remote:        peer,
			cachedCommand: &connCommand{cancel: make(chan struct{}), result: make(chan error, 1)},
		},
	}
	c.driver = &connDriver{conn: c}
	return c
}

func (c *Conn) deliver(data []byte, peer netip.AddrPort) {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	if c.shared.err != nil || len(c.config.incoming) == cap(c.config.incoming) || len(data) > maxIncomingBytes-c.shared.incomingBytes || !c.config.packetBudget.reserve(len(data)) {
		return
	}
	select {
	case c.config.incoming <- incomingPacket{bytes.Clone(data), peer}:
		c.shared.incomingBytes += len(data)
	default:
		c.config.packetBudget.release(len(data))
	}
}

func (c *Conn) releasePacket(size int) {
	c.shared.mu.Lock()
	c.shared.incomingBytes -= size
	c.shared.mu.Unlock()
	c.config.packetBudget.release(size)
}

func (c *Conn) signalLocked() {
	close(c.shared.notify)
	c.shared.notify = make(chan struct{})
}

func (c *Conn) signalWake() {
	select {
	case c.config.wake <- struct{}{}:
	default:
	}
}

func (c *Conn) fail(err error) {
	c.shutdown(err, false)
}

func (c *Conn) shutdown(err error, notify bool) {
	c.shared.once.Do(func() {
		c.shared.mu.Lock()
		c.shared.err = err
		c.shared.closeNotify = notify
		if c.config.transport != nil {
			c.config.transport.cancelWrite(c.config.stop)
		} else {
			close(c.config.stop)
		}
		c.signalLocked()
		c.shared.mu.Unlock()
	})
}

func (c *Conn) failure() error {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	if c.shared.err != nil {
		return c.shared.err
	}
	return net.ErrClosed
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
			c.shared.mu.Lock()
			if c.shared.cachedCommand == nil {
				c.shared.cachedCommand = command
			}
			c.shared.mu.Unlock()
		} else {
			c.config.transport.cancelWrite(command.cancel)
		}
		c.signalWake()
	}()
	var reply <-chan error
	for {
		c.shared.mu.Lock()
		deadline, notify := c.shared.writeDeadline, c.shared.notify
		c.shared.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		commands := c.config.commands
		if reply != nil {
			commands = nil
		}
		var err error
		done := false
		select {
		case commands <- command:
			reply = command.result
		case err = <-reply:
			reusable = err == nil && command.kind == commandWrite
			done = true
		case <-c.config.stop:
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
	c.shared.mu.Lock()
	if len(data) > c.shared.maxDatagram {
		c.shared.mu.Unlock()
		return 0, errRecordOverflow
	}
	command := c.shared.cachedCommand
	c.shared.cachedCommand = nil
	c.shared.mu.Unlock()
	if command == nil {
		command = &connCommand{}
	}
	// A deadline can return before the session finishes encoding this command.
	*command = connCommand{kind: commandWrite, data: bytes.Clone(data), cancel: command.cancel, result: command.result}
	if err := c.execute(command); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *Conn) Read(data []byte) (int, error) {
	for {
		c.shared.mu.Lock()
		if c.shared.err != nil {
			err := c.shared.err
			c.shared.mu.Unlock()
			return 0, err
		}
		if len(c.shared.readQueue) != 0 {
			packet := c.shared.readQueue[0]
			c.shared.readBytes -= cap(packet)
			c.shared.readQueue[0] = nil
			if len(c.shared.readQueue) == 1 {
				c.shared.readQueue = c.shared.readQueue[:0]
			} else {
				c.shared.readQueue = c.shared.readQueue[1:]
			}
			c.shared.mu.Unlock()
			return copy(data, packet), nil
		}
		if c.shared.peerEOF {
			c.shared.mu.Unlock()
			return 0, io.EOF
		}
		deadline, notify := c.shared.readDeadline, c.shared.notify
		c.shared.mu.Unlock()
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
	<-c.config.done
	return nil
}

func (c *Conn) CloseWrite() error { return c.execute(&connCommand{kind: commandCloseWrite}) }

// UpdateKeys waits until the peer acknowledges new sending keys.
func (c *Conn) UpdateKeys(requestPeer bool) error {
	return c.execute(&connCommand{kind: commandUpdateKeys, requestPeer: requestPeer})
}

// RotateConnectionID asks the peer to replace the CID it sends immediately.
func (c *Conn) RotateConnectionID() error {
	return c.execute(&connCommand{kind: commandRotateCID})
}

func (c *Conn) LocalAddr() net.Addr { return c.config.transport.conn.LocalAddr() }

func (c *Conn) RemoteAddr() net.Addr {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	return net.UDPAddrFromAddrPort(c.shared.remote)
}

func (c *Conn) ConnectionState() tls.ConnectionState {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	return c.shared.state
}

// TLSConnectionState exposes authenticated peer metadata to endpoint wrappers.
func (c *Conn) TLSConnectionState() (tls.ConnectionState, bool) {
	state := c.ConnectionState()
	return state, state.HandshakeComplete
}

func (c *Conn) MaxDatagramSize() int {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	return c.shared.maxDatagram
}

func (c *Conn) SetDeadline(t time.Time) error     { return c.setDeadlines(t, t, true, true) }
func (c *Conn) SetReadDeadline(t time.Time) error { return c.setDeadlines(t, time.Time{}, true, false) }
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.setDeadlines(time.Time{}, t, false, true)
}

func (c *Conn) setDeadlines(read, write time.Time, setRead, setWrite bool) error {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	if c.shared.err != nil {
		return c.shared.err
	}
	if setRead {
		c.shared.readDeadline = read
	}
	if setWrite {
		c.shared.writeDeadline = write
	}
	c.signalLocked()
	c.signalWake()
	return nil
}

func (d *connDriver) attach(s *session) {
	d.session = s
	c := d.conn
	if c.config.transport != nil {
		s.working.canProbe = c.config.transport.unfragmented
	}
	s.path = &pathState{session: s, peer: packetPath{c.shared.remote, 1}, allowPeer: s.handshake.config.AcceptPeer,
		send: func(to packetPath, data []byte) error {
			return c.config.transport.write(data, to.remote, time.Time{}, c.config.stop)
		}, changed: func(to packetPath) {
			c.shared.mu.Lock()
			c.shared.remote = to.remote
			c.signalLocked()
			c.shared.mu.Unlock()
			if c.config.onPeerChanged != nil {
				c.config.onPeerChanged(c, to.remote)
			}
		}}
}

func (d *connDriver) sendPacket(data []byte) error {
	if d.session != nil && !d.cookieValidated && !d.session.handshake.client && !d.session.handshake.complete && d.session.handshake.schedule == nil {
		if uint64(len(data)) > d.handshakeCredit {
			return nil
		}
		d.handshakeCredit -= uint64(len(data))
	}
	c := d.conn
	c.shared.mu.Lock()
	peer, deadline := c.shared.remote, c.shared.writeDeadline
	c.shared.mu.Unlock()
	if command := d.sendingApplication; command != nil {
		return c.config.transport.writeApplication(data, peer, deadline, c.config.stop, command.cancel)
	}
	return c.config.transport.write(data, peer, time.Time{}, c.config.stop)
}

func (d *connDriver) run() {
	c := d.conn
	s := d.session
	d.abort = false
	defer d.teardown()
	d.started = time.Now()
	select {
	case <-c.config.stop:
		return
	default:
	}
	if err := s.processHandshakes(d.started); err != nil {
		d.abort = true
		_, _ = s.sendRecord(s.currentWriteEpoch(), contentAlert, errorAlert(err))
		c.fail(err)
		return
	}
	d.handshakeDeadline = time.Time{}
	if !s.handshake.config.DisableHandshakeTimeout {
		d.handshakeDeadline = d.started.Add(s.handshake.config.HandshakeTimeout)
	}
	d.ready = false
	d.queuedBeforeTimeout = -1
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-c.config.stop:
			return
		default:
		}
		now := time.Now()
		waitDeadline := time.Time{}
		if !d.ready {
			// HandshakeTimeout stays active until the final flight is sent.
			waitDeadline = d.handshakeDeadline
			if !d.handshakeDeadline.IsZero() && !now.Before(d.handshakeDeadline) {
				c.fail(context.DeadlineExceeded)
				return
			}
		}
		if !s.handshake.complete {
			if timeout := s.handshake.config.HandshakeReadTimeout; timeout > 0 && (s.outbound == nil || !s.outbound.pendingSend()) {
				lastReceive := s.handshakeReceived
				if lastReceive.IsZero() {
					lastReceive = d.started
				}
				deadline := lastReceive.Add(timeout)
				if !now.Before(deadline) {
					// Give the existing queue one chance; new junk cannot prolong expiry.
					if d.queuedBeforeTimeout < 0 {
						d.queuedBeforeTimeout = len(c.config.incoming)
					}
					if d.queuedBeforeTimeout == 0 {
						c.fail(ErrHandshakeReadTimeout)
						return
					}
					packet := <-c.config.incoming
					d.queuedBeforeTimeout--
					if !d.receivePacket(packet) {
						return
					}
					if s.handshakeReceived.After(lastReceive) {
						d.queuedBeforeTimeout = -1
					}
					continue
				}
				if waitDeadline.IsZero() || deadline.Before(waitDeadline) {
					waitDeadline = deadline
				}
			}
		}
		d.queuedBeforeTimeout = -1
		if err := s.tick(now); err != nil {
			d.abort = !errors.Is(err, net.ErrClosed)
			c.fail(err)
			return
		}
		d.publishMaxDatagram()
		if s.handshake.complete && s.handshakeFlightSent() && !d.ready {
			if err := s.sendACK(); err != nil {
				d.abort = !errors.Is(err, net.ErrClosed)
				c.fail(err)
				return
			}
			// Only change fragmentation when the peer can answer MTU probes.
			if c.config.owned && s.handshake.rrc && s.handshake.cidNegotiated {
				c.config.transport.configureUnfragmentedProbes(s.handshake.config.UnfragmentedProbes)
				s.working.canProbe = c.config.transport.unfragmented
				if s.working.canProbe {
					c.signalWake()
				}
			}
			d.ready = true
			s.cid.want = true
			d.publish(nil)
			close(c.config.ready)
			if c.config.onReady != nil && !c.config.onReady(c) {
				return
			}
		}
		if d.pending != nil {
			select {
			case <-d.pending.cancel:
				d.pending = nil
			default:
				if done, err := d.command(d.pending, now); done {
					result := d.pending.result
					d.pending = nil
					result <- err
				}
			}
		}
		deadline := s.deadline()
		if !d.ready && !waitDeadline.IsZero() && (deadline.IsZero() || waitDeadline.Before(deadline)) {
			deadline = waitDeadline
		}
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer.Reset(time.Until(deadline))
			timerC = timer.C
		}
		commands := c.config.commands
		if d.pending != nil {
			commands = nil
		}
		select {
		case <-c.config.stop:
			return
		case <-timerC:
		case <-c.config.wake:
		case d.pending = <-commands:
		case packet := <-c.config.incoming:
			if !d.receivePacket(packet) {
				return
			}
		}
	}
}

func (d *connDriver) receivePacket(packet incomingPacket) bool {
	c := d.conn
	s := d.session
	c.releasePacket(len(packet.data))
	select {
	case <-c.config.stop:
		return false
	default:
	}
	if !d.ready && !d.handshakeDeadline.IsZero() && !time.Now().Before(d.handshakeDeadline) {
		c.fail(context.DeadlineExceeded)
		return false
	}
	if !s.handshake.client && !s.handshake.complete && s.handshake.schedule == nil {
		d.handshakeCredit = min(1<<30, d.handshakeCredit+3*uint64(len(packet.data)))
	}
	data, err := s.receiveFrom(packet.data, packetPath{packet.peer, 1}, time.Now())
	if err != nil {
		d.abort = !errors.Is(err, net.ErrClosed)
		if d.abort {
			_, _ = s.sendRecord(s.currentWriteEpoch(), contentAlert, errorAlert(err))
		}
		c.fail(err)
		return false
	}
	d.publish(data)
	return true
}

func (d *connDriver) teardown() {
	c := d.conn
	s := d.session
	d.pending = nil
	c.fail(net.ErrClosed)
	// Close may interrupt a control write before the stop case runs.
	if c.shared.closeNotify && !d.abort && s.handshake.complete && !d.writeClosed {
		_, _ = s.sendRecordWith(s.currentWriteEpoch(), contentAlert, []byte{1, 0}, s.handshake.peerCID,
			func(data []byte) error { return c.config.transport.write(data, s.path.peer.remote, time.Time{}, nil) })
	}
	s.reassembly.clear()
	for len(c.config.incoming) != 0 {
		packet := <-c.config.incoming
		c.releasePacket(len(packet.data))
	}
	if c.config.owned {
		c.config.transport.close(net.ErrClosed)
	}
	if c.config.onClose != nil {
		c.config.onClose(c)
	}
	close(c.config.done)
}

func (d *connDriver) publish(data [][]byte) {
	c := d.conn
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	wasEmpty := len(c.shared.readQueue) == 0
	queued := false
	for _, packet := range data {
		if len(c.shared.readQueue) < maxQueuedRecords && cap(packet) <= maxApplicationBytes-c.shared.readBytes && !c.shared.peerEOF {
			// Decryption transfers ownership; charge retained padding and capacity too.
			c.shared.readQueue = append(c.shared.readQueue, packet)
			c.shared.readBytes += cap(packet)
			queued = true
		}
	}
	eof := d.session.peerClosed != nil
	changed := queued && wasEmpty || eof != c.shared.peerEOF
	c.shared.peerEOF = eof
	c.shared.state = d.session.handshake.state
	c.shared.maxDatagram = d.datagramBudget()
	if changed {
		c.signalLocked()
	}
}

func (d *connDriver) datagramBudget() int {
	cidLength := 0
	if d.session.handshake.cidNegotiated {
		cidLength = len(d.session.handshake.peerCID)
	}
	n := min(maxContent, d.session.effectiveMTU()-datagramOverhead(cidLength, defaultAEADTag))
	if n < 0 {
		return 0
	}
	return n
}

func (d *connDriver) publishMaxDatagram() {
	n := d.datagramBudget()
	c := d.conn
	c.shared.mu.Lock()
	c.shared.maxDatagram = n
	c.shared.mu.Unlock()
}

func (d *connDriver) command(command *connCommand, now time.Time) (bool, error) {
	c := d.conn
	c.shared.mu.Lock()
	deadline := c.shared.writeDeadline
	c.shared.mu.Unlock()
	if !deadline.IsZero() && !now.Before(deadline) {
		return true, os.ErrDeadlineExceeded
	}
	s := d.session
	var err error
	switch command.kind {
	case commandWrite:
		if d.writeClosed {
			return true, net.ErrClosed
		}
		d.sendingApplication = command
		err = s.application(command.data)
		d.sendingApplication = nil
		if isMessageTooLong(err) {
			d.publishMaxDatagram()
		}
		if errors.Is(err, errOperationPending) {
			if e := s.advancePost(now); e != nil {
				return true, e
			}
		}
	case commandUpdateKeys:
		if !command.started {
			command.epoch = s.currentWriteEpoch()
			if s.keyUpdate.updating {
				command.epoch++
			}
			err = s.requestKeyUpdate(command.requestPeer, now)
			command.started = err == nil
		}
		if err == nil && s.currentWriteEpoch() <= command.epoch {
			return false, nil
		}
	case commandRotateCID:
		if !command.started {
			err = s.provideCIDs(1, true, now)
			command.started = err == nil
		}
		if err == nil && s.post[msgNewConnectionID] != nil {
			return false, nil
		}
	case commandCloseWrite:
		if d.writeClosed {
			return true, nil
		}
		if s.keyUpdate.updating || s.keyUpdate.localPending {
			return false, nil
		}
		_, err = s.sendRecord(s.currentWriteEpoch(), contentAlert, []byte{1, 0})
		if err == nil {
			d.writeClosed = true
		}
	default:
		return true, errUnexpectedMessage
	}
	if errors.Is(err, errWritePending) {
		c.signalWake()
		return false, nil
	}
	if errors.Is(err, errOperationPending) || errors.Is(err, errPathPending) {
		return false, nil
	}
	if errors.Is(err, errSequence) {
		c.fail(err)
	}
	return true, err
}
