//go:build linux

package netopen

import (
	"encoding/binary"
	"math"
)

func sockaddrHeader(family int) []byte {
	hdr := make([]byte, 2)
	binary.NativeEndian.PutUint16(hdr, uint16(family)) // #nosec G115 -- packRawSockaddr rejects out-of-range family
	return hdr
}

func sockaddrFamily(buf []byte) int {
	if len(buf) < 2 {
		return 0
	}
	return int(binary.NativeEndian.Uint16(buf[:2]))
}

func setSockaddrLen([]byte) {}

func sockaddrFamilyMax() int { return math.MaxUint16 }
