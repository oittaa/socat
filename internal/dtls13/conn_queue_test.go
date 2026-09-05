package dtls13

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
)

func TestConnQueuesPacketizedBurst(t *testing.T) {
	c := newConn(netip.AddrPort{})
	c.packetBudget = &memoryBudget{limit: maxIncomingBytes}
	c.session = &session{handshake: &handshakeState{config: &Config{MTU: 1200}}}
	for i := range 40 {
		c.deliver(bytes.Repeat([]byte{byte(i)}, 1200), netip.AddrPort{})
	}
	if len(c.incoming) != 40 {
		t.Fatalf("dropped packetized burst: %d of 40 queued", len(c.incoming))
	}
	for i := range 40 {
		packet := <-c.incoming
		c.releasePacket(len(packet.data))
		c.publish([][]byte{packet.data[:1170]})
		if packet.data[0] != byte(i) {
			t.Fatal("incoming order changed")
		}
	}
	c.peerEOF = true
	buffer := make([]byte, 1200)
	for i := range 40 {
		n, err := c.Read(buffer)
		if n != 1170 || err != nil || !bytes.Equal(buffer[:n], bytes.Repeat([]byte{byte(i)}, 1170)) {
			t.Fatalf("application record %d: %d, %v", i, n, err)
		}
	}
	if _, err := c.Read(buffer); err != io.EOF {
		t.Fatalf("end of burst: %v", err)
	}
	if c.readBytes != 0 || c.incomingBytes != 0 || c.packetBudget.used.Load() != 0 {
		t.Fatal("queue budget not released")
	}
}

func TestConnQueueMemoryBounds(t *testing.T) {
	c := newConn(netip.AddrPort{})
	c.packetBudget = &memoryBudget{limit: maxIncomingBytes * 2}
	c.session = &session{handshake: &handshakeState{config: &Config{MTU: 1200}}}
	for range 100 {
		c.deliver(make([]byte, 65535), netip.AddrPort{})
		c.publish([][]byte{make([]byte, maxContent)})
	}
	if c.incomingBytes > maxIncomingBytes || c.readBytes > maxApplicationBytes {
		t.Fatal("byte budget exceeded")
	}
	if c.incomingBytes != maxIncomingBytes || c.readBytes != maxApplicationBytes {
		t.Fatal("queue did not fill to byte limit")
	}
	for len(c.incoming) > 0 {
		p := <-c.incoming
		c.releasePacket(len(p.data))
	}
	for len(c.readQueue) > 0 {
		if _, err := c.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	// Empty application messages still consume a record slot.
	for range maxQueuedRecords + 1 {
		c.publish([][]byte{nil})
		c.deliver([]byte{1}, netip.AddrPort{})
	}
	if len(c.readQueue) != maxQueuedRecords || len(c.incoming) != maxQueuedRecords {
		t.Fatal("record count bound was not enforced")
	}
}
