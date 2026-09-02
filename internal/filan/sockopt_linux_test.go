//go:build linux

package filan

import "testing"

func TestTCPInfoWscalesEndian(t *testing.T) {
	const packed = byte(0xab) // high nibble 0xa, low nibble 0xb
	snd, rcv := tcpInfoWscales(packed, false)
	if snd != 0xb || rcv != 0xa {
		t.Fatalf("little-endian snd=%d rcv=%d want 11,10", snd, rcv)
	}
	snd, rcv = tcpInfoWscales(packed, true)
	if snd != 0xa || rcv != 0xb {
		t.Fatalf("big-endian snd=%d rcv=%d want 10,11", snd, rcv)
	}
}
