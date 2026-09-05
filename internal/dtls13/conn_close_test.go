package dtls13

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type interruptedControlConn struct {
	net.PacketConn
	entered, release chan struct{}
	packets          chan []byte
	interrupted      bool
}

func (p *interruptedControlConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	if !p.interrupted {
		p.interrupted = true
		close(p.entered)
		<-p.release
		return 0, net.ErrClosed
	}
	p.packets <- bytes.Clone(data)
	return len(data), nil
}

func TestConnCloseDuringControlWrite(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		for _, cause := range []string{"close", "protocol_failure"} {
			t.Run(role+"/"+cause, func(t *testing.T) {
				clientConfig, serverConfig := handshakeConfigs(t)
				s, peer, _ := driveSessions(t, clientConfig, serverConfig, false, false)
				if role == "server" {
					s, peer = peer, s
				}
				s.acknowledgements = []recordNumber{{epoch: 3, sequence: 0}}
				s.ackDeadline = time.Unix(1, 0)
				p := &interruptedControlConn{PacketConn: testUDP(t), entered: make(chan struct{}),
					release: make(chan struct{}), packets: make(chan []byte, 4)}
				release := sync.OnceFunc(func() { close(p.release) })
				c := newConn(netip.MustParseAddrPort("127.0.0.1:12345"))
				c.owned = true
				c.transport = newPacketTransport(p, nil, nil)
				c.attach(s)
				s.send = c.sendPacket
				writerDone := make(chan struct{})
				go func() { c.transport.writeLoop(); close(writerDone) }()
				go c.run()
				t.Cleanup(func() { release(); _ = c.Close(); <-writerDone })
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				select {
				case <-p.entered:
				case <-ctx.Done():
					t.Fatal("control write did not start")
				}
				if cause == "protocol_failure" {
					c.fail(errUnexpectedMessage)
				}
				closed := make(chan struct{})
				go func() { _ = c.Close(); close(closed) }()
				select {
				case <-c.stop:
				case <-ctx.Done():
					t.Fatal("Close did not interrupt the control write")
				}
				release()
				select {
				case <-closed:
				case <-ctx.Done():
					t.Fatal("Close did not finish")
				}
				<-writerDone
				if cause == "protocol_failure" {
					if c.failure() != errUnexpectedMessage || len(p.packets) != 0 {
						t.Fatal("Close replaced a protocol failure with graceful closure")
					}
					return
				}
				if len(p.packets) != 1 {
					t.Fatalf("Close sent %d records after the interrupted ACK, want one close_notify", len(p.packets))
				}
				if _, err := peer.receive(<-p.packets, time.Now()); err != nil || peer.peerClosed == nil {
					t.Fatalf("peer did not receive an authenticated close_notify: %v", err)
				}
			})
		}
	}
}
