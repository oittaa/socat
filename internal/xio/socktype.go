package xio

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
)

// SocketTypeOption reads socktype / so-type. When the option is absent it
// returns def (typically syscall.SOCK_STREAM) and explicit=false.
func SocketTypeOption(s parse.Spec, def int) (typ int, explicit bool, err error) {
	o, ok := s.OptionNamed("socktype")
	if !ok {
		return def, false, nil
	}
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, true, fmt.Errorf("%s: option %q requires a socket type number", s.Type, o.Name)
	}
	n, err := strconv.Atoi(o.Value)
	if err != nil {
		return 0, true, fmt.Errorf("%s: invalid %s=%q", s.Type, o.Name, o.Value)
	}
	switch n {
	case syscall.SOCK_STREAM, syscall.SOCK_DGRAM:
		return n, true, nil
	case syscall.SOCK_SEQPACKET:
		if !FeatureUNIXSeqpacket {
			return 0, true, fmt.Errorf("%s: %s=%d (SOCK_SEQPACKET) is not supported on this platform", s.Type, o.Name, n)
		}
		return n, true, nil
	default:
		return 0, true, fmt.Errorf("%s: unsupported %s=%d", s.Type, o.Name, n)
	}
}
