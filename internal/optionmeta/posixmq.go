package optionmeta

var posixMQOptions = []Option{
	{Canonical: "mq-prio", Kind: KindMQPrio, Aliases: []string{"posixmq-priority"},
		Desc:  "message priority",
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
	{Canonical: "mq-flush", Kind: KindBool, Aliases: []string{"posixmq-flush"},
		Desc:  "drain the queue before use",
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
	{Canonical: "mq-maxmsg", Kind: KindInt, Min: 0, Aliases: []string{"posixmq-maxmsg"},
		Desc:  "maximum number of messages in a new queue",
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
	{Canonical: "mq-msgsize", Kind: KindInt, Min: 0, Aliases: []string{"posixmq-msgsize"},
		Desc:  "maximum message size in a new queue",
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
}
