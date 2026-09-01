package netopen

import "io"

// copyOneshotFirst delivers a buffered *-RECVFROM datagram. An empty packet
// is EOF (null-eof, or a raw IPv4 header with no payload).
func copyOneshotFirst(p, first []byte) (int, error) {
	if len(first) == 0 {
		return 0, io.EOF
	}
	return copy(p, first), nil
}
