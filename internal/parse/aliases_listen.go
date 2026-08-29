package parse

func init() {
	registerOptionAliases(map[string]string{ // #nosec G101 -- option names, not secrets
		"listen-timeout":            "accept-timeout",
		"ignoreof":                  "ignoreeof",
		"addrconfig":                "ai-addrconfig",
		"passive":                   "ai-passive",
		"v4mapped":                  "ai-v4mapped",
		"protocol-family":           "pf",
		"bytes":                     "readbytes",
		"crlf":                      "crnl",
		"maxchildren":               "max-children",
		"intervall":                 "interval",
		"ipv6only":                  "ipv6-v6only",
		"v6only":                    "ipv6-v6only",
		"child-shutup":              "children-shutup",
		"tcpwrappers":               "tcpwrap",
		"tcpwrapper":                "tcpwrap",
		"libwrap":                   "tcpwrap",
		"wrap":                      "tcpwrap",
		"tcpwrap-dir":               "tcpwrap-etc",
		"allow-table":               "hosts-allow",
		"tcpwrap-hosts-allow-table": "hosts-allow",
		"deny-table":                "hosts-deny",
		"tcpwrap-hosts-deny-table":  "hosts-deny",
	})
}
