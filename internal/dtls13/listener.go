package dtls13

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

// Listener owns one UDP transport. Closing it also closes its associations.
type Listener struct {
	mu          sync.Mutex
	transport   *packetTransport
	config      *Config
	accepted    chan *Conn
	done        chan struct{}
	acceptDone  chan struct{}
	acceptErr   error
	err         error
	connections map[*Conn]bool
	handshakes  map[netip.AddrPort]*Conn
	established map[netip.AddrPort]*Conn
	cids        map[string]*Conn
	packets     memoryBudget
	fragments   memoryBudget
}

// Listen takes ownership of transport after validating the configuration.
func Listen(transport net.PacketConn, config *Config) (*Listener, error) {
	prepared, err := prepareConfig(config, true)
	if err != nil {
		return nil, err
	}
	if transport == nil {
		return nil, errors.New("dtls: packet transport is required")
	}
	if _, err := udpAddress(transport.LocalAddr()); err != nil {
		return nil, err
	}
	l := &Listener{config: prepared, accepted: make(chan *Conn, prepared.MaxConnections), done: make(chan struct{}), acceptDone: make(chan struct{}),
		connections: make(map[*Conn]bool), handshakes: make(map[netip.AddrPort]*Conn), established: make(map[netip.AddrPort]*Conn), cids: make(map[string]*Conn),
		packets: memoryBudget{limit: 8 << 20}, fragments: memoryBudget{limit: 16 << 20}}
	l.transport = newPacketTransport(transport, l.receive, l.shutdown)
	l.transport.start()
	return l, nil
}

func (l *Listener) receive(data []byte, peer netip.AddrPort) {
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return
	}
	var connection *Conn
	var established *Conn
	initial := false
	for rest := data; len(rest) != 0; {
		r, tail, err := parseRecord(rest, l.config.ConnectionIDLength)
		if err != nil {
			l.mu.Unlock()
			return
		}
		if len(r.cid) != 0 {
			connection = l.cids[string(r.cid)]
			break
		}
		if !r.encrypted && r.typ == contentHandshake {
			f, _, err := parseFragment(r.body)
			initial = initial || err == nil && f.typ == msgClientHello
		}
		rest = tail
	}
	if connection == nil && initial {
		if l.acceptErr != nil {
			l.mu.Unlock()
			return
		}
		connection = l.handshakes[peer]
		if connection == nil && l.config.AcceptPeer != nil {
			l.mu.Unlock()
			allowed := l.config.AcceptPeer(peer)
			l.mu.Lock()
			if !allowed || l.err != nil || l.acceptErr != nil {
				l.mu.Unlock()
				return
			}
		}
		if connection == nil && len(l.connections) < l.config.MaxConnections && len(l.handshakes) < 16 {
			state, err := preparedHandshakeState(l.config, false)
			if err == nil && (len(state.localCID) == 0 || l.cids[string(state.localCID)] == nil) {
				connection = newConn(peer)
				connection.transport, connection.packetBudget = l.transport, &l.packets
				h := &serverHandshake{handshakeState: state, phase: msgClientHello}
				s := newSession(state, h.handle, connection.sendPacket)
				s.reassembly.budget = &l.fragments
				connection.attach(s)
				connection.onReady, connection.onClose, connection.onPeerChanged = l.establish, l.remove, l.peerChanged
				s.setLocalCIDs = func(ids [][]byte) error { return l.setCIDs(connection, ids) }
				l.connections[connection] = true
				l.handshakes[peer] = connection
				if len(state.localCID) != 0 {
					l.cids[string(state.localCID)] = connection
				}
				go connection.run()
			}
		}
	}
	if connection == nil && !initial {
		connection = l.handshakes[peer]
		established = l.established[peer]
		if connection == nil {
			connection, established = established, nil
		}
	}
	l.mu.Unlock()
	if connection != nil {
		connection.deliver(data, peer)
	}
	// A new unauthenticated handshake must not displace an existing no-CID peer.
	if established != nil && established != connection {
		established.deliver(data, peer)
	}
}

func (l *Listener) establish(c *Conn) bool {
	peer, _ := udpAddress(c.RemoteAddr())
	l.mu.Lock()
	if l.err != nil || l.acceptErr != nil || len(l.accepted) == cap(l.accepted) {
		l.mu.Unlock()
		return false
	}
	previous := l.established[peer]
	l.established[peer] = c
	delete(l.handshakes, peer)
	l.connections[c] = false
	l.accepted <- c
	l.mu.Unlock()
	if previous != nil && previous != c {
		previous.fail(net.ErrClosed)
	}
	return true
}

func (l *Listener) setCIDs(c *Conn, ids [][]byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	for _, id := range ids {
		if owner := l.cids[string(id)]; owner != nil && owner != c {
			return errors.New("dtls: connection ID collision")
		}
	}
	for id, owner := range l.cids {
		if owner == c {
			delete(l.cids, id)
		}
	}
	for _, id := range ids {
		l.cids[string(id)] = c
	}
	return nil
}

func (l *Listener) peerChanged(c *Conn, peer netip.AddrPort) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for address, owner := range l.established {
		if owner == c {
			delete(l.established, address)
		}
	}
	l.established[peer] = c
}

func (l *Listener) remove(c *Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.connections, c)
	for _, index := range []map[netip.AddrPort]*Conn{l.handshakes, l.established} {
		for address, owner := range index {
			if owner == c {
				delete(index, address)
			}
		}
	}
	for id, owner := range l.cids {
		if owner == c {
			delete(l.cids, id)
		}
	}
}

func (l *Listener) shutdown(err error) {
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return
	}
	l.err = err
	close(l.done)
	connections := make([]*Conn, 0, len(l.connections))
	for c := range l.connections {
		connections = append(connections, c)
	}
	l.mu.Unlock()
	for _, c := range connections {
		c.fail(err)
	}
	l.transport.close(err)
}

func (l *Listener) Accept() (net.Conn, error) { return l.AcceptContext(context.Background()) }

func (l *Listener) AcceptContext(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case c := <-l.accepted:
			l.mu.Lock()
			acceptErr := l.acceptErr
			l.mu.Unlock()
			if acceptErr != nil {
				c.fail(acceptErr)
				return nil, acceptErr
			}
			select {
			case <-c.stop:
				continue
			default:
				return c, nil
			}
		case <-l.done:
			l.mu.Lock()
			err := l.err
			l.mu.Unlock()
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.acceptDone:
			return nil, net.ErrClosed
		}
	}
}

// StopAccept stops admission while allowing accepted associations to finish.
// Close must still be called to release the shared UDP transport.
func (l *Listener) StopAccept() error {
	l.mu.Lock()
	if l.acceptErr != nil {
		l.mu.Unlock()
		return nil
	}
	l.acceptErr = net.ErrClosed
	close(l.acceptDone)
	var pending []*Conn
	for c, handshaking := range l.connections {
		if handshaking {
			pending = append(pending, c)
		}
	}
	l.mu.Unlock()
	for _, c := range pending {
		c.fail(net.ErrClosed)
	}
	return nil
}

func (l *Listener) Close() error   { l.shutdown(net.ErrClosed); return nil }
func (l *Listener) Addr() net.Addr { return l.transport.conn.LocalAddr() }
