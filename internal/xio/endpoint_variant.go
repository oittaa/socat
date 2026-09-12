package xio

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/relay"
)

// Endpoint ownership. Each Opened holds exactly one private payload.
//
//	Variant              | Payload owns                                      | Opened teardown
//	-------------------- | ------------------------------------------------- | ----------------
//	ready I/O            | Stream (combined for dual), EXEC childDone        | tty restore, Cleanup
//	accept parent        | Listener, peer filter, accept-timeout,            | Cleanup (may also
//	                     | fork-socketpair, parent knobs                     | close the listener)
//	repeated-dial parent | Dial, interval, parent knobs                      | Cleanup
//	deferred nofork      | EXEC/SYSTEM/SHELL address (started after peer)    | Cleanup
//
// Parent knobs (accept + repeated-dial only): MaxChildren, ChildrenShutup,
// WrapDial, HandshakeTimeout.
//
// Invalid combinations (ready I/O plus a listener, nofork plus a dialer, …)
// have no representation. Kind() is derived from the payload so it cannot
// diverge. Today's Run switch still uses Kind(); a later PR will dispatch
// on the payload instead.

// openedPayload is the exclusive live state of one Opened.
type openedPayload interface {
	kind() OpenedKind
	close() error
}

type parentKnobs struct {
	maxChildren      int
	childrenShutup   int
	wrapDial         func(net.Conn) (relay.Stream, error)
	handshakeTimeout time.Duration
}

type readyIO struct {
	stream    relay.Stream
	childDone <-chan struct{}
}

var (
	errReadyRequiresStream    = errors.New("xio: ready endpoint requires a stream")
	errReadySplitRequiresIO   = errors.New("xio: ready-split endpoint requires read and write streams")
	errAcceptRequiresListener = errors.New("xio: accept parent requires a listener")
	errRepeatRequiresDialer   = errors.New("xio: repeated-dial parent requires a dialer")
)

func (p *readyIO) kind() OpenedKind { return KindReady }

func (p *readyIO) close() error {
	if p == nil || p.stream == nil {
		return nil
	}
	return p.stream.Close()
}

type acceptParent struct {
	listener       net.Listener
	forkSocketpair bool
	peerFilter     func(net.Conn) error
	acceptTimeout  time.Duration
	knobs          parentKnobs
}

func (p *acceptParent) kind() OpenedKind { return KindListen }

func (p *acceptParent) close() error {
	if p == nil || p.listener == nil {
		return nil
	}
	err := p.listener.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

type repeatedDial struct {
	dial     func(context.Context) (net.Conn, error)
	interval time.Duration
	knobs    parentKnobs
}

func (p *repeatedDial) kind() OpenedKind { return KindDial }

func (p *repeatedDial) close() error { return nil }

type deferredNoFork struct {
	config addrconfig.Address
}

func (p *deferredNoFork) kind() OpenedKind { return KindExec }

func (p *deferredNoFork) close() error { return nil }

// AcceptParent is the listen/fork parent passed to NewAcceptParent.
type AcceptParent struct {
	Listener         net.Listener
	ForkSocketpair   bool
	PeerFilter       func(net.Conn) error
	AcceptTimeout    time.Duration
	MaxChildren      int
	WrapDial         func(net.Conn) (relay.Stream, error)
	HandshakeTimeout time.Duration
}

// RepeatedDial is the CONNECT,fork (or similar) parent passed to NewRepeatedDial.
type RepeatedDial struct {
	Dial             func(context.Context) (net.Conn, error)
	Interval         time.Duration
	MaxChildren      int
	WrapDial         func(net.Conn) (relay.Stream, error)
	HandshakeTimeout time.Duration
}

// NewReady returns a transfer-ready endpoint that owns stream.
func NewReady(label string, stream relay.Stream) (*Opened, error) {
	if stream == nil {
		return nil, errReadyRequiresStream
	}
	return newOpened(label, &readyIO{stream: stream}), nil
}

// NewReadySplit returns a dual-address ready endpoint. read and write become
// one combined stream owned for Close.
func NewReadySplit(label string, read, write relay.Stream) (*Opened, error) {
	if read == nil || write == nil {
		return nil, errReadySplitRequiresIO
	}
	return NewReady(label, relay.FDStream{
		R: read,
		W: write,
		C: NewMultiCloser(read, write),
		CloseW: func() error {
			return write.ShutdownWrite()
		},
	})
}

// NewAcceptParent returns a bound accept/fork parent that owns p.Listener.
func NewAcceptParent(label string, p AcceptParent) (*Opened, error) {
	if p.Listener == nil {
		return nil, errAcceptRequiresListener
	}
	return newOpened(label, &acceptParent{
		listener:       p.Listener,
		forkSocketpair: p.ForkSocketpair,
		peerFilter:     p.PeerFilter,
		acceptTimeout:  p.AcceptTimeout,
		knobs: parentKnobs{
			maxChildren:      p.MaxChildren,
			wrapDial:         p.WrapDial,
			handshakeTimeout: p.HandshakeTimeout,
		},
	}), nil
}

// NewRepeatedDial returns a repeated-connect parent. Live conns are not owned
// until a child wraps them.
func NewRepeatedDial(label string, p RepeatedDial) (*Opened, error) {
	if p.Dial == nil {
		return nil, errRepeatRequiresDialer
	}
	return newOpened(label, &repeatedDial{
		dial:     p.Dial,
		interval: p.Interval,
		knobs: parentKnobs{
			maxChildren:      p.MaxChildren,
			wrapDial:         p.WrapDial,
			handshakeTimeout: p.HandshakeTimeout,
		},
	}), nil
}

// NewDeferredNoFork returns EXEC/SYSTEM/SHELL,nofork. Run starts the process
// after the peer stream is open.
func NewDeferredNoFork(label string, cfg addrconfig.Address) *Opened {
	return newOpened(label, &deferredNoFork{config: cfg})
}

func newOpened(label string, payload openedPayload) *Opened {
	return &Opened{Label: label, payload: payload}
}

// Kind reports the payload variant. It is derived, so it cannot diverge
// from the live endpoint.
func (o *Opened) Kind() OpenedKind {
	if o == nil || o.payload == nil {
		return 0
	}
	return o.payload.kind()
}

func (o *Opened) ready() *readyIO {
	if o == nil {
		return nil
	}
	p, _ := o.payload.(*readyIO)
	return p
}

func (o *Opened) accept() *acceptParent {
	if o == nil {
		return nil
	}
	p, _ := o.payload.(*acceptParent)
	return p
}

func (o *Opened) repeated() *repeatedDial {
	if o == nil {
		return nil
	}
	p, _ := o.payload.(*repeatedDial)
	return p
}

func (o *Opened) nofork() *deferredNoFork {
	if o == nil {
		return nil
	}
	p, _ := o.payload.(*deferredNoFork)
	return p
}

func (o *Opened) knobs() *parentKnobs {
	if p := o.accept(); p != nil {
		return &p.knobs
	}
	if p := o.repeated(); p != nil {
		return &p.knobs
	}
	return nil
}

// Stream is the ready-I/O transfer stream. Other variants return nil.
func (o *Opened) Stream() relay.Stream {
	if p := o.ready(); p != nil {
		return p.stream
	}
	return nil
}

// Listener is the accept-parent socket. Other variants return nil.
func (o *Opened) Listener() net.Listener {
	if p := o.accept(); p != nil {
		return p.listener
	}
	return nil
}

// Dial is the repeated-dial function. Other variants return nil.
func (o *Opened) Dial() func(context.Context) (net.Conn, error) {
	if p := o.repeated(); p != nil {
		return p.dial
	}
	return nil
}

// NoForkConfig is the deferred nofork address. Other variants return nil.
func (o *Opened) NoForkConfig() *addrconfig.Address {
	if p := o.nofork(); p != nil {
		return &p.config
	}
	return nil
}

// Interval is the repeated-dial pause. Other variants return 0.
func (o *Opened) Interval() time.Duration {
	if p := o.repeated(); p != nil {
		return p.interval
	}
	return 0
}

// ForkSocketpair is set on datagram accept parents that bridge children.
func (o *Opened) ForkSocketpair() bool {
	if p := o.accept(); p != nil {
		return p.forkSocketpair
	}
	return false
}

// PeerFilter is the accept-parent refuse callback. Other variants return nil.
func (o *Opened) PeerFilter() func(net.Conn) error {
	if p := o.accept(); p != nil {
		return p.peerFilter
	}
	return nil
}

// AcceptTimeout is the accept-parent wait. Other variants return 0.
func (o *Opened) AcceptTimeout() time.Duration {
	if p := o.accept(); p != nil {
		return p.acceptTimeout
	}
	return 0
}

// MaxChildren bounds accept and repeated-dial parents. Other variants return 0.
func (o *Opened) MaxChildren() int {
	if k := o.knobs(); k != nil {
		return k.maxChildren
	}
	return 0
}

// ChildrenShutup is the parent-knob diagnostic demotion. Other variants return 0.
func (o *Opened) ChildrenShutup() int {
	if k := o.knobs(); k != nil {
		return k.childrenShutup
	}
	return 0
}

// SetChildrenShutup records children-shutup on accept and repeated-dial
// parents. Ready I/O and deferred nofork ignore it.
func (o *Opened) SetChildrenShutup(n int) {
	if k := o.knobs(); k != nil {
		k.childrenShutup = n
	}
}

// WrapDial wraps each accepted or dialed connection. Other variants return nil.
func (o *Opened) WrapDial() func(net.Conn) (relay.Stream, error) {
	if k := o.knobs(); k != nil {
		return k.wrapDial
	}
	return nil
}

// HandshakeTimeout is the parent-knob TLS/handshake wait. Other variants return 0.
func (o *Opened) HandshakeTimeout() time.Duration {
	if k := o.knobs(); k != nil {
		return k.handshakeTimeout
	}
	return 0
}

func (o *Opened) childDone() <-chan struct{} {
	if p := o.ready(); p != nil {
		return p.childDone
	}
	return nil
}

func (o *Opened) setChildDone(done <-chan struct{}) {
	if p := o.ready(); p != nil {
		p.childDone = done
	}
}
