package dtls13

import "testing"

func TestWireVectorBoundaries(t *testing.T) {
	for _, size := range []int{8, 16, 24} {
		w := wireWriter{}
		switch size {
		case 8:
			w.vector8([]byte{1, 2, 3})
		case 16:
			w.vector16([]byte{1, 2, 3})
		case 24:
			w.vector24([]byte{1, 2, 3})
		}
		wire, err := w.result()
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n <= len(wire); n++ {
			r := wireReader{data: wire[:n]}
			var got []byte
			switch size {
			case 8:
				got = r.vector8()
			case 16:
				got = r.vector16()
			case 24:
				got = r.vector24()
			}
			if n == len(wire) {
				if r.done() != nil || len(got) != 3 || got[2] != 3 {
					t.Fatal("valid vector failed")
				}
			} else if r.done() == nil {
				t.Fatalf("accepted %d-bit truncated vector at %d", size, n)
			}
		}
	}
	for _, size := range []int{8, 16, 24} {
		w := wireWriter{}
		switch size {
		case 8:
			w.vector8(make([]byte, 256))
		case 16:
			w.vector16(make([]byte, 65536))
		case 24:
			w.uint24(1 << 24)
		}
		w.uint8(1)
		if _, err := w.result(); err == nil {
			t.Fatal("writer lost an overflow error")
		}
	}
	reader := wireReader{data: []byte{1}}
	if reader.take(-1) != nil {
		t.Fatal("accepted a negative length")
	}
	if reader.uint8() != 0 || reader.done() == nil {
		t.Fatal("reader lost its error state")
	}
}
