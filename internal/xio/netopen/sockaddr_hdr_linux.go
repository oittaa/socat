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

func setSockaddrLen([]byte) {}

func sockaddrFamilyMax() int { return math.MaxUint16 }
