package cli

// POSIX-MQ, TUN/INTERFACE, and namespace options.
func tunOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"POSIX message queues", []helpOpt{
			{name: "mq-prio", desc: "message priority", aliases: []string{"posixmq-priority"}, validate: validateInteger(0)},
			{name: "mq-flush", desc: "drain the queue before use", aliases: []string{"posixmq-flush"}},
			{name: "mq-maxmsg", desc: "mq_maxmsg", aliases: []string{"posixmq-maxmsg"}, validate: validateInteger(0)},
			{name: "mq-msgsize", desc: "mq_msgsize", aliases: []string{"posixmq-msgsize"}, validate: validateInteger(0)},
		}},
		{"TUN and INTERFACE", []helpOpt{
			{name: "tun-device", desc: "path to the TUN clone device"},
			{name: "tun-name", desc: "TUN/TAP interface name"},
			{name: "tun-type", desc: "tun or tap"},
			{name: "iff-no-pi", desc: "no packet information header", aliases: []string{"no-pi", "tun-no-pi"}, validate: validateOptionalBool},
			{name: "iff-up", desc: "bring the interface up", aliases: []string{"up"}, validate: validateOptionalBool},
			{name: "iff-broadcast", desc: "IFF_BROADCAST", validate: validateOptionalBool},
			{name: "iff-debug", desc: "IFF_DEBUG", validate: validateOptionalBool},
			{name: "iff-loopback", desc: "IFF_LOOPBACK", aliases: []string{"loopback"}, validate: validateOptionalBool},
			{name: "iff-pointopoint", desc: "IFF_POINTOPOINT", aliases: []string{"pointopoint"}, validate: validateOptionalBool},
			{name: "iff-running", desc: "IFF_RUNNING", aliases: []string{"running"}, validate: validateOptionalBool},
			{name: "iff-noarp", desc: "IFF_NOARP", aliases: []string{"noarp"}, validate: validateOptionalBool},
			{name: "iff-promisc", desc: "IFF_PROMISC", aliases: []string{"promisc"}, validate: validateOptionalBool},
			{name: "iff-allmulti", desc: "IFF_ALLMULTI", aliases: []string{"allmulti"}, validate: validateOptionalBool},
			{name: "iff-multicast", desc: "IFF_MULTICAST", aliases: []string{"multicast"}, validate: validateOptionalBool},
			{name: "iff-notrailers", desc: "IFF_NOTRAILERS", aliases: []string{"notrailers"}, validate: validateOptionalBool},
			{name: "iff-master", desc: "IFF_MASTER", aliases: []string{"master"}, validate: validateOptionalBool},
			{name: "iff-slave", desc: "IFF_SLAVE", aliases: []string{"slave"}, validate: validateOptionalBool},
			{name: "iff-portsel", desc: "IFF_PORTSEL", aliases: []string{"portsel"}, validate: validateOptionalBool},
			{name: "iff-automedia", desc: "IFF_AUTOMEDIA", aliases: []string{"automedia"}, validate: validateOptionalBool},
			{name: "if-mtu", desc: "interface MTU", aliases: []string{"interface-mtu"}, validate: validateInt64(true)},
		}},
		{"Namespaces", []helpOpt{
			{name: "netns", desc: "open this address in a Linux network namespace"},
		}},
	}
}
