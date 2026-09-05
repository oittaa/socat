package dtls13

import (
	"encoding/binary"
)

// wireReader keeps nested vector parsing within the enclosing message.
type wireReader struct {
	data []byte
	err  error
}

func (r *wireReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.data) {
		r.err = errDecode
		return nil
	}
	v := r.data[:n]
	r.data = r.data[n:]
	return v
}

func (r *wireReader) uint8() byte {
	b := r.take(1)
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func (r *wireReader) uint16() uint16 {
	b := r.take(2)
	if len(b) == 0 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *wireReader) uint24() int {
	b := r.take(3)
	if len(b) == 0 {
		return 0
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

func (r *wireReader) vector8() []byte  { return r.take(int(r.uint8())) }
func (r *wireReader) vector16() []byte { return r.take(int(r.uint16())) }
func (r *wireReader) vector24() []byte { return r.take(r.uint24()) }

func (r *wireReader) done() error {
	if r.err != nil || len(r.data) != 0 {
		return errDecode
	}
	return nil
}

type wireWriter struct {
	data []byte
	err  error
}

func (w *wireWriter) uint8(v byte)    { w.data = append(w.data, v) }
func (w *wireWriter) uint16(v uint16) { w.data = binary.BigEndian.AppendUint16(w.data, v) }

func (w *wireWriter) uint24(v int) {
	if v < 0 || v > 0xffffff {
		w.err = errDecode
		return
	}
	w.data = append(w.data, byte(v>>16&0xff), byte(v>>8&0xff), byte(v&0xff))
}

func (w *wireWriter) vector8(v []byte) {
	n := len(v)
	if n > 255 {
		w.err = errDecode
		return
	}
	w.uint8(byte(n))
	w.data = append(w.data, v...)
}

func (w *wireWriter) vector16(v []byte) {
	n := len(v)
	if n > 65535 {
		w.err = errDecode
		return
	}
	w.uint16(uint16(n))
	w.data = append(w.data, v...)
}

func (w *wireWriter) vector24(v []byte) {
	if len(v) > 0xffffff {
		w.err = errDecode
		return
	}
	w.uint24(len(v))
	w.data = append(w.data, v...)
}

func (w *wireWriter) result() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.data, nil
}
