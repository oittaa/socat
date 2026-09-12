package xio

import (
	"fmt"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
)

// SocketTypeOption reads socktype / so-type. When the option is absent it
// returns def (typically syscall.SOCK_STREAM) and explicit=false.
func SocketTypeOption(s addrconfig.Address, def int) (typ int, explicit bool, err error) {
	return ConfiguredSocketType(s, s.Type, def)
}

// ConfiguredSocketType returns the prepared socktype, or def when unset.
func ConfiguredSocketType(config addrconfig.Address, addressType string, def int) (typ int, explicit bool, err error) {
	if !config.Network.SocketType.Set {
		return def, false, nil
	}
	n := config.Network.SocketType.Value
	switch n {
	case syscall.SOCK_STREAM, syscall.SOCK_DGRAM:
		return n, true, nil
	case syscall.SOCK_SEQPACKET:
		if !FeatureUNIXSeqpacket {
			return 0, true, fmt.Errorf("%s: %s=%d (SOCK_SEQPACKET) is not supported on this platform", addressType, "socktype", n)
		}
		return n, true, nil
	default:
		return 0, true, fmt.Errorf("%s: unsupported socktype=%d", addressType, n)
	}
}
