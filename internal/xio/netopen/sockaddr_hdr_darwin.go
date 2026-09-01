//go:build darwin

package netopen

func sockaddrHeader(family int) []byte {
	return []byte{0, byte(family)} // #nosec G115 -- packRawSockaddr rejects family > 255; sa_family is uint8
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
