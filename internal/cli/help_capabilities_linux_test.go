//go:build linux

package cli

func expectedUnixCapabilities() (datagram, seqpacket bool) {
	return true, true
}
