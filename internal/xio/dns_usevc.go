package xio

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type resolverDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// resolverRewriteDNSTransport implements classic xio_res_init RES_USEVC without
// mutating process-global _res. Setting Dial implies PreferGo.
//
// forceTCP true (res-usevc): rewrite udp* to tcp* so DNS is TCP-only.
// forceTCP false (res-usevc=0): clear RES_USEVC. UDP Dials stay UDP. A TCP
// Dial after that UDP (Go's truncation retry) uses real TCP so the sequence
// is UDP then TCP, not UDP then another UDP-then-TCP. A TCP Dial with no
// prior UDP (resolv.conf use-vc) still speaks DNS-over-TCP framing to the
// caller, sends the first query over UDP, and retries over TCP when the UDP
// response has the TC bit. Returning a UDP PacketConn for a TCP Dial would
// make Go skip that retry (it already believes it used TCP).
func resolverRewriteDNSTransport(base *net.Resolver, forceTCP bool) *net.Resolver {
	if base == nil {
		base = net.DefaultResolver
	}
	inner := base.Dial
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if inner != nil {
			return inner(ctx, network, address)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	// Per LookupResolver Dial closure, not process-global: parallel lookups
	// each get their own resolver from resolverRewriteDNSTransport.
	var usedUDP atomic.Bool
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: base.StrictErrors,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if forceTCP {
				if strings.HasPrefix(network, "udp") {
					network = "tcp" + strings.TrimPrefix(network, "udp")
				}
				return dial(ctx, network, address)
			}
			if strings.HasPrefix(network, "udp") {
				usedUDP.Store(true)
				return dial(ctx, network, address)
			}
			if strings.HasPrefix(network, "tcp") {
				if usedUDP.Load() {
					return dial(ctx, network, address)
				}
				return newDNSUDPThenTCPConn(ctx, dial, network, address), nil
			}
			return dial(ctx, network, address)
		},
	}
}

var _ net.Conn = (*dnsUDPThenTCPConn)(nil)

func dnsUDPNetwork(tcpNetwork string) string {
	return "udp" + strings.TrimPrefix(tcpNetwork, "tcp")
}

func newDNSUDPThenTCPConn(ctx context.Context, dial resolverDialFunc, tcpNetwork, address string) *dnsUDPThenTCPConn {
	return &dnsUDPThenTCPConn{
		ctx:        ctx,
		dial:       dial,
		udpNetwork: dnsUDPNetwork(tcpNetwork),
		tcpNetwork: tcpNetwork,
		address:    address,
	}
}

// dnsUDPThenTCPConn is a DNS-over-TCP stream that clears RES_USEVC: the first
// query is UDP, and a TC-bit response is retried over TCP with length prefixes.
// It must not implement net.PacketConn.
type dnsUDPThenTCPConn struct {
	ctx        context.Context
	dial       resolverDialFunc
	udpNetwork string
	tcpNetwork string
	address    string

	mu       sync.Mutex
	writeBuf []byte
	readBuf  []byte
	inner    net.Conn
	closed   bool
	deadline time.Time
	rdl      time.Time
	wdl      time.Time
}

func (c *dnsUDPThenTCPConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writeBuf = append(c.writeBuf, p...)
	if err := c.flushLocked(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *dnsUDPThenTCPConn) flushLocked() error {
	for {
		if len(c.writeBuf) < 2 {
			return nil
		}
		n := int(binary.BigEndian.Uint16(c.writeBuf[:2]))
		if len(c.writeBuf) < 2+n {
			return nil
		}
		query := append([]byte(nil), c.writeBuf[2:2+n]...)
		c.writeBuf = c.writeBuf[2+n:]
		resp, err := c.exchangeLocked(query)
		if err != nil {
			return err
		}
		framed, err := frameDNSTCPMessage(resp)
		if err != nil {
			return err
		}
		c.readBuf = append(c.readBuf, framed...)
	}
}

func (c *dnsUDPThenTCPConn) exchangeLocked(query []byte) ([]byte, error) {
	udp, err := c.dial(c.ctx, c.udpNetwork, c.address)
	if err != nil {
		return nil, err
	}
	c.replaceInnerLocked(udp)
	if err := c.applyDeadlinesLocked(udp); err != nil {
		return nil, err
	}
	if _, err := udp.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := udp.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := append([]byte(nil), buf[:n]...)
	if !dnsMessageTruncated(resp) {
		return resp, nil
	}
	_ = udp.Close()
	c.inner = nil
	return c.exchangeTCPLocked(query)
}

func (c *dnsUDPThenTCPConn) exchangeTCPLocked(query []byte) ([]byte, error) {
	tcp, err := c.dial(c.ctx, c.tcpNetwork, c.address)
	if err != nil {
		return nil, err
	}
	c.replaceInnerLocked(tcp)
	if err := c.applyDeadlinesLocked(tcp); err != nil {
		return nil, err
	}
	framed, err := frameDNSTCPMessage(query)
	if err != nil {
		return nil, err
	}
	if _, err := tcp.Write(framed); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(tcp, hdr[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(hdr[:])))
	if _, err := io.ReadFull(tcp, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *dnsUDPThenTCPConn) replaceInnerLocked(next net.Conn) {
	if c.inner != nil && c.inner != next {
		_ = c.inner.Close()
	}
	c.inner = next
}

func (c *dnsUDPThenTCPConn) applyDeadlinesLocked(conn net.Conn) error {
	if !c.deadline.IsZero() {
		return conn.SetDeadline(c.deadline)
	}
	if !c.rdl.IsZero() {
		if err := conn.SetReadDeadline(c.rdl); err != nil {
			return err
		}
	}
	if !c.wdl.IsZero() {
		return conn.SetWriteDeadline(c.wdl)
	}
	return nil
}

func (c *dnsUDPThenTCPConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if err := c.flushLocked(); err != nil {
		return 0, err
	}
	if len(c.readBuf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *dnsUDPThenTCPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.inner == nil {
		return nil
	}
	err := c.inner.Close()
	c.inner = nil
	return err
}

func (c *dnsUDPThenTCPConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner != nil {
		return c.inner.LocalAddr()
	}
	return &net.TCPAddr{}
}

func (c *dnsUDPThenTCPConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner != nil {
		return c.inner.RemoteAddr()
	}
	return &net.TCPAddr{}
}

func (c *dnsUDPThenTCPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	c.rdl = time.Time{}
	c.wdl = time.Time{}
	if c.inner != nil {
		return c.inner.SetDeadline(t)
	}
	return nil
}

func (c *dnsUDPThenTCPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdl = t
	if c.inner != nil {
		return c.inner.SetReadDeadline(t)
	}
	return nil
}

func (c *dnsUDPThenTCPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wdl = t
	if c.inner != nil {
		return c.inner.SetWriteDeadline(t)
	}
	return nil
}

func dnsMessageTruncated(msg []byte) bool {
	return len(msg) >= 3 && msg[2]&0x02 != 0
}

func frameDNSTCPMessage(msg []byte) ([]byte, error) {
	n := len(msg)
	if n > math.MaxUint16 {
		return nil, errDNSTCPTooLong
	}
	framed := make([]byte, 2+n)
	binary.BigEndian.PutUint16(framed[:2], uint16(n))
	copy(framed[2:], msg)
	return framed, nil
}

var errDNSTCPTooLong = errors.New("dns: message exceeds 16-bit TCP length")
