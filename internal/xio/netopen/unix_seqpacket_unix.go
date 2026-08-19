//go:build unix

package netopen

func unixSeqpacketNetwork() (string, bool) {
	return "unixpacket", true
}
