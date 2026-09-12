package posixmqopen

import (
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
)

type mqKind int

const (
	mqBidir mqKind = iota
	mqRead
	mqRecv
	mqSend
)

func kindOf(s addrconfig.Address) mqKind {
	switch s.Facts.Role {
	case addrconfig.AddressRoleReceive:
		return mqRead
	case addrconfig.AddressRoleReceiveFrom:
		return mqRecv
	case addrconfig.AddressRoleSendTo:
		return mqSend
	default:
		return mqBidir
	}
}

func queueName(s addrconfig.Address) (string, error) {
	if len(s.Params) > 1 {
		return "", fmt.Errorf("too many parameters (%d instead of 1)", len(s.Params))
	}
	if len(s.Params) != 1 || s.Params[0] == "" {
		return "", fmt.Errorf("%s: requires a queue name", s.Type)
	}
	return s.Params[0], nil
}
