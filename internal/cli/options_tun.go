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
			{name: "iff-no-pi", desc: "no packet information header", aliases: []string{"no-pi", "tun-no-pi"}},
			{name: "iff-up", desc: "bring the interface up", aliases: []string{"up"}},
			{name: "iff-broadcast", desc: "IFF_BROADCAST"},
			{name: "iff-debug", desc: "IFF_DEBUG"},
			{name: "iff-loopback", desc: "IFF_LOOPBACK", aliases: []string{"loopback"}},
			{name: "iff-pointopoint", desc: "IFF_POINTOPOINT", aliases: []string{"pointopoint"}},
			{name: "iff-running", desc: "IFF_RUNNING", aliases: []string{"running"}},
			{name: "iff-noarp", desc: "IFF_NOARP", aliases: []string{"noarp"}},
			{name: "iff-promisc", desc: "IFF_PROMISC", aliases: []string{"promisc"}},
			{name: "iff-allmulti", desc: "IFF_ALLMULTI", aliases: []string{"allmulti"}},
			{name: "iff-multicast", desc: "IFF_MULTICAST", aliases: []string{"multicast"}},
			{name: "if-mtu", desc: "interface MTU", aliases: []string{"interface-mtu"}, validate: validateInt64(true)},
			{name: "retrieve-vlan", desc: "restore 802.1Q from PACKET_AUXDATA on INTERFACE", addressTypes: []string{"INTERFACE"}, restrictAddressTypes: true, validate: validateNoValue},
		}},
		{"Namespaces", []helpOpt{
			{name: "netns", desc: "open this address in a Linux network namespace"},
		}},
	}
}
