//go:build darwin || windows

package sockopt

import "fmt"

func recvErrSupported() bool { return false }

func applyRecvErrValue(_ int, _ int) error {
	return fmt.Errorf("ip-recverr: not supported (no MSG_ERRQUEUE ReadMsg path)")
}
