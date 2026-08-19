//go:build linux

package netopen

func unixSeqpacketNetwork() (string, bool) {
	return "unixpacket", true
}
