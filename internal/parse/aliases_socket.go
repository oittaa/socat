package parse

func init() {
	registerOptionAliases(map[string]string{
		"so-reuseaddr": "reuseaddr",
		"so-reuseport": "reuseport",
		// ipv6-join-group is a distinct classic option (GROUP_IP6 only,
		// tag-1.8.1.3 / 12c08bf). Do not fold it onto ip-add-membership
		// (IP4+IP6); validation is spelling-specific. Same-group nicknames
		// from classic -hhh fold onto their canonical descriptor.
		"add-membership":      "ip-add-membership",
		"ip-membership":       "ip-add-membership",
		"membership":          "ip-add-membership",
		"ipv6-add-membership": "ipv6-join-group",
		"join-group":          "ipv6-join-group",
		"so-keepalive":        "keepalive",
		"so-bindtodevice":     "bindtodevice",
		"if":                  "bindtodevice",
		"interface":           "bindtodevice",
		"so-broadcast":        "broadcast",
		"so-rcvbuf":           "rcvbuf",
		"so-sndbuf":           "sndbuf",
		"so-rcvbuf-late":      "rcvbuf-late",
		"so-sndbuf-late":      "sndbuf-late",
		"so-rcvtimeo":         "rcvtimeo",
		"so-sndtimeo":         "sndtimeo",
		"so-prototype":        "so-protocol",
		"prototype":           "so-protocol",
		"tcp-nodelay":         "nodelay",
		"tcp-keepalive":       "keepalive",
		"so-keepidle":         "keepidle",
		"so-keepintvl":        "keepintvl",
		"so-keepcnt":          "keepcnt",
		"tcp-keepidle":        "keepidle",
		"tcp-keepintvl":       "keepintvl",
		"tcp-keepcnt":         "keepcnt",
		"ipttl":               "ip-ttl",
		"iptos":               "ip-tos",
		"sp":                  "sourceport",
		"sourceport":          "sourceport",
		"sockopt-listen":      "setsockopt-listen",
	})
}
