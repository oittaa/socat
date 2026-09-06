package dtls13

import "testing"

func TestTakeBufferReusesFirstFit(t *testing.T) {
	var free [][]byte
	first := takeBuffer(&free, 8)
	copy(first, "abcdefgh")
	putBuffer(&free, first, 4, 64)
	second := takeBuffer(&free, 4)
	if cap(second) != cap(first) || &second[0] != &first[0] {
		t.Fatal("did not reuse a large enough recycled buffer")
	}
	if len(free) != 0 {
		t.Fatal("reused buffer remained in the free list")
	}
	putBuffer(&free, make([]byte, 0, 128), 4, 64)
	if len(free) != 0 {
		t.Fatal("stored a buffer larger than maxCap")
	}
}
