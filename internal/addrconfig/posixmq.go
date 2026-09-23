package addrconfig

func decodePOSIXMQPositional(n *Network, params []string) error {
	if len(params) > 1 {
		return parameterCountError(len(params), 1, 1)
	}
	n.MQName = firstParam(params)
	return nil
}
