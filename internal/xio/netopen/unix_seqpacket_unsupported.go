//go:build darwin || windows

package netopen

func unixSeqpacketNetwork() (string, bool) {
	return "", false
}
