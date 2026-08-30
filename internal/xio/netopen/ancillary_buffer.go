package netopen

import "github.com/oittaa/socat/internal/xio"

func ancillaryBuffer(buf *[]byte, enabled bool) []byte {
	if !enabled {
		return nil
	}
	if *buf == nil {
		*buf = make([]byte, xio.AncillaryBufferSize)
	}
	return *buf
}
