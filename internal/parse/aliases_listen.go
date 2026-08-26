package parse

func init() {
	registerOptionAliases(map[string]string{
		"listen-timeout":  "accept-timeout",
		"ignoreof":        "ignoreeof",
		"addrconfig":      "ai-addrconfig",
		"protocol-family": "pf",
	})
}
