package parse

func init() {
	registerOptionAliases(map[string]string{
		"posixmq-priority": "mq-prio",
		"posixmq-flush":    "mq-flush",
		"posixmq-maxmsg":   "mq-maxmsg",
		"posixmq-msgsize":  "mq-msgsize",
		"no-pi":            "iff-no-pi",
		"tun-no-pi":        "iff-no-pi",
		"up":               "iff-up",
		"loopback":         "iff-loopback",
		"pointopoint":      "iff-pointopoint",
		"running":          "iff-running",
		"noarp":            "iff-noarp",
		"promisc":          "iff-promisc",
		"allmulti":         "iff-allmulti",
		"multicast":        "iff-multicast",
		"interface-mtu":    "if-mtu",
	})
}
