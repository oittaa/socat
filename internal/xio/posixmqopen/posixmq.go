package posixmqopen

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

type mqKind int

const (
	mqBidir mqKind = iota
	mqRead
	mqRecv
	mqSend
)

func kindOf(typ string) mqKind {
	switch typ {
	case "POSIXMQ-READ":
		return mqRead
	case "POSIXMQ-RECEIVE", "POSIXMQ-RECV":
		return mqRecv
	case "POSIXMQ-SEND", "POSIXMQ-WRITE":
		return mqSend
	default:
		return mqBidir
	}
}

func queueName(s parse.Spec) (string, error) {
	if len(s.Params) > 1 {
		return "", fmt.Errorf("too many parameters (%d instead of 1)", len(s.Params))
	}
	if len(s.Params) != 1 || s.Params[0] == "" {
		return "", fmt.Errorf("%s: requires a queue name", s.Type)
	}
	return s.Params[0], nil
}
