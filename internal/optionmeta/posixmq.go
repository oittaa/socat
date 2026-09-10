package optionmeta

var posixMQOptions = []Option{
	{Canonical: "mq-prio", Aliases: []string{"posixmq-priority"},
		Desc: "message priority", Value: IntegerMin0,
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
	{Canonical: "mq-flush", Aliases: []string{"posixmq-flush"},
		Desc:  "drain the queue before use",
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
	{Canonical: "mq-maxmsg", Aliases: []string{"posixmq-maxmsg"},
		Desc: "maximum number of messages in a new queue", Value: IntegerMin0,
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
	{Canonical: "mq-msgsize", Aliases: []string{"posixmq-msgsize"},
		Desc: "maximum message size in a new queue", Value: IntegerMin0,
		Scope: AddressScope{Caps: capPOSIXMQ, AddressGroups: []string{GroupPOSIXMQ}},
	},
}
