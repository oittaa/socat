//go:build !linux

package netopen

func unixSeqpacketNetwork() (string, bool) {
	return "", false
}
