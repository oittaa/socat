package addrconfig

import (
	"fmt"
	"strconv"

	"github.com/oittaa/socat/internal/parse"
)

func decodePOSIXMQPositional(n *Network, params []string) error {
	if len(params) > 1 {
		return fmt.Errorf("too many parameters (%d instead of 1)", len(params))
	}
	n.MQName = firstParam(params)
	return nil
}

func decodePOSIXMQOption(n *Network, o parse.Option, name string) (bool, error) {
	switch name {
	case "mq-prio":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		v, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return true, fmt.Errorf("invalid mq-prio %q", value)
		}
		n.MQPriority = OptionalUint32{Set: true, Value: uint32(v)}
	case "mq-flush":
		return true, setActive(&n.MQFlush, o)
	case "mq-maxmsg":
		return true, setRequiredInt(&n.MQMaxMessages, o, 0)
	case "mq-msgsize":
		return true, setRequiredInt(&n.MQMessageSize, o, 0)
	default:
		return false, nil
	}
	return true, nil
}
