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
	if s.Network.MQName == "" {
		return "", fmt.Errorf("%s: requires a queue name", s.Type)
	}
	return s.Network.MQName, nil
}
