package dtls13

import (
	"net/netip"
	"testing"
)

func TestConnQueueChargesRetainedCapacity(t *testing.T) {
	c := newConn(netip.AddrPort{})
	c.session = &session{handshake: &handshakeState{config: &Config{MTU: 1200}}}
	packet := make([]byte, 1, maxApplicationBytes)
	packet[0] = 'a'
	c.publish([][]byte{packet, []byte("overflow")})
	if c.readBytes != maxApplicationBytes || len(c.readQueue) != 1 {
		t.Fatalf("retained capacity bypassed queue bound: bytes=%d records=%d", c.readBytes, len(c.readQueue))
	}
	var buffer [8]byte
	if n, err := c.Read(buffer[:]); n != 1 || err != nil || buffer[0] != 'a' {
		t.Fatalf("read = %d, %v, %q", n, err, buffer[:n])
	}
	if c.readBytes != 0 {
		t.Fatal("retained capacity was not released")
	}
}
