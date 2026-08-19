//go:build darwin

package cli

func expectedUnixCapabilities() (datagram, seqpacket bool) {
	return true, false
}
