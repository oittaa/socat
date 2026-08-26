package parse

func init() {
	registerOptionAliases(map[string]string{
		"posixmq-priority": "mq-prio",
		"posixmq-flush":    "mq-flush",
		"posixmq-maxmsg":   "mq-maxmsg",
		"posixmq-msgsize":  "mq-msgsize",
	})
}
