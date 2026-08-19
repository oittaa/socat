//go:build windows

package cli

func expectedUnixCapabilities() (datagram, seqpacket bool) {
	return false, false
}
