//go:build darwin

package netopen

import "math"

func sockaddrHeader(family int) []byte {
	if family < 0 || family > math.MaxUint8 {
		return nil
	}
	return []byte{0, byte(family)}
}

func sockaddrFamily(buf []byte) int {
	if len(buf) < 2 {
		return 0
	}
	return int(buf[1])
}

func setSockaddrLen(buf []byte) {
	if len(buf) == 0 {
		return
	}
	n := len(buf)
	if n > 255 {
		n = 255
	}
	buf[0] = byte(n)
}

func sockaddrFamilyMax() int { return 255 }
