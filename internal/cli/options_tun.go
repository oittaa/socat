package cli

// POSIX-MQ, TUN/INTERFACE, and namespace options.
func tunOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"POSIX message queues", []helpOpt{
			{name: "mq-prio", optionCaps: capPOSIXMQ, desc: "message priority", aliases: []string{"posixmq-priority"}, validate: validateInteger(0)},
			{name: "mq-flush", optionCaps: capPOSIXMQ, desc: "drain the queue before use", aliases: []string{"posixmq-flush"}},
			{name: "mq-maxmsg", optionCaps: capPOSIXMQ, desc: "mq_maxmsg", aliases: []string{"posixmq-maxmsg"}, validate: validateInteger(0)},
			{name: "mq-msgsize", optionCaps: capPOSIXMQ, desc: "mq_msgsize", aliases: []string{"posixmq-msgsize"}, validate: validateInteger(0)},
		}},
		{"TUN and INTERFACE", []helpOpt{
			{name: "tun-device", optionCaps: capInterface, desc: "path to the TUN clone device"},
			{name: "tun-name", optionCaps: capInterface, desc: "TUN/TAP interface name"},
			{name: "tun-type", optionCaps: capInterface, desc: "tun or tap"},
			{name: "iff-no-pi", optionCaps: capInterface, desc: "no packet information header", aliases: []string{"no-pi", "tun-no-pi"}, validate: validateOptionalBool},
			{name: "iff-up", optionCaps: capInterface, desc: "bring the interface up", aliases: []string{"up"}, validate: validateOptionalBool},
			{name: "iff-broadcast", optionCaps: capInterface, desc: "IFF_BROADCAST", validate: validateOptionalBool},
			{name: "iff-debug", optionCaps: capInterface, desc: "IFF_DEBUG", validate: validateOptionalBool},
			{name: "iff-loopback", optionCaps: capInterface, desc: "IFF_LOOPBACK", aliases: []string{"loopback"}, validate: validateOptionalBool},
			{name: "iff-pointopoint", optionCaps: capInterface, desc: "IFF_POINTOPOINT", aliases: []string{"pointopoint"}, validate: validateOptionalBool},
			{name: "iff-running", optionCaps: capInterface, desc: "IFF_RUNNING", aliases: []string{"running"}, validate: validateOptionalBool},
			{name: "iff-noarp", optionCaps: capInterface, desc: "IFF_NOARP", aliases: []string{"noarp"}, validate: validateOptionalBool},
			{name: "iff-promisc", optionCaps: capInterface, desc: "IFF_PROMISC", aliases: []string{"promisc"}, validate: validateOptionalBool},
			{name: "iff-allmulti", optionCaps: capInterface, desc: "IFF_ALLMULTI", aliases: []string{"allmulti"}, validate: validateOptionalBool},
			{name: "iff-multicast", optionCaps: capInterface, desc: "IFF_MULTICAST", aliases: []string{"multicast"}, validate: validateOptionalBool},
			{name: "iff-notrailers", optionCaps: capInterface, desc: "IFF_NOTRAILERS", aliases: []string{"notrailers"}, validate: validateOptionalBool},
			{name: "iff-master", optionCaps: capInterface, desc: "IFF_MASTER", aliases: []string{"master"}, validate: validateOptionalBool},
			{name: "iff-slave", optionCaps: capInterface, desc: "IFF_SLAVE", aliases: []string{"slave"}, validate: validateOptionalBool},
			{name: "iff-portsel", optionCaps: capInterface, desc: "IFF_PORTSEL", aliases: []string{"portsel"}, validate: validateOptionalBool},
			{name: "iff-automedia", optionCaps: capInterface, desc: "IFF_AUTOMEDIA", aliases: []string{"automedia"}, validate: validateOptionalBool},
			{name: "if-mtu", optionCaps: capInterface, desc: "interface MTU", aliases: []string{"interface-mtu"}, validate: validateInt64(true)},
			{name: "retrieve-vlan", optionCaps: capInterface, desc: "restore 802.1Q from PACKET_AUXDATA on INTERFACE", addressTypes: []string{"INTERFACE"}, restrictAddressTypes: true, validate: validateNoValue},
		}},
		{"Namespaces", []helpOpt{
			{name: "netns", unrestricted: true, desc: "open this address in a Linux network namespace"},
		}},
	}
}
