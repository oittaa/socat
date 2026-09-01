package cli

// Listen, connect, and security-filter options.
func listenOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Listen and connect", []helpOpt{
			{name: "reuseaddr", optionCaps: capSocket, desc: "SO_REUSEADDR (TCP listen default on; UDP-LISTEN with fork or this option)", aliases: []string{"so-reuseaddr"}},
			{name: "reuseport", optionCaps: capSocket, desc: "SO_REUSEPORT", aliases: []string{"so-reuseport"}},
			{name: "fork", optionCaps: capChild, desc: "new session per accept or client redial"},
			{name: "nofork", optionCaps: capFork, desc: "do not fork (single session)"},
			{name: "max-children", optionCaps: capChild, desc: "limit concurrent fork sessions (needs fork)", aliases: []string{"maxchildren"}, validate: validateInteger(1)},
			{name: "children-shutup", optionCaps: capChild, desc: "lower fork-child log severity", aliases: []string{"child-shutup"}, validate: validateOptionalInteger(0)},
			{name: "bind", optionCaps: capSocket, desc: "local address or interface"},
			{name: "connect-timeout", optionCaps: capSocket, desc: "connect timeout", validate: validateDurationOption},
			{name: "handshake-timeout", desc: "TLS, WebSocket, QUIC, PROXY, or SOCKS handshake timeout", addressTypes: handshakeAddressTypes(), validate: validateDurationOption},
			{name: "accept-timeout", optionCaps: capListen, desc: "listen accept timeout (exit 0)", aliases: []string{"listen-timeout"}, validate: validateDurationOption},
			{name: "backlog", optionCaps: capListen, desc: "listen backlog", addressTypes: backlogListenAddressTypes(), validate: validateInteger(1)},
			{name: "pf", optionCaps: capSocket, desc: "address family (4, 6, IP4, IP6, …)", aliases: []string{"protocol-family"}},
			{name: "ai-addrconfig", optionCaps: capIP4IP6, desc: "skip addresses whose family is not configured on this host (default on without a family hint; =0 disables)", aliases: []string{"addrconfig"}, addressTypes: resolverAddressTypes(), implementationGroups: resolverImplementationGroups(), validate: validateOptionalBool},
			{name: "ai-passive", optionCaps: capIP4IP6, desc: "use wildcard addresses for listen/bind (default); =0 uses loopback, and dual-stack connect prefers IPv6", aliases: []string{"passive"}, addressTypes: resolverAddressTypes(), implementationGroups: resolverImplementationGroups(), validate: validateOptionalBool},
			{name: "ai-v4mapped", optionCaps: capIP4IP6, desc: "map IPv4 answers onto IPv6 lookups (off unless set)", aliases: []string{"v4mapped"}, addressTypes: resolverAddressTypes(), implementationGroups: resolverImplementationGroups(), validate: validateOptionalBool},
			{name: "ai-all", optionCaps: capIP4IP6, desc: "with ai-v4mapped, also return mapped IPv4 answers when IPv6 answers exist", addressTypes: resolverAddressTypes(), implementationGroups: resolverImplementationGroups(), validate: validateOptionalBool},
			{name: "ipv6-v6only", optionCaps: capIP6, desc: "IPV6_V6ONLY", aliases: []string{"ipv6only", "v6only"}},
			{name: "retry", optionCaps: capRetry, desc: "retry count on connect failure", validate: validateInteger(-1)},
			{name: "forever", optionCaps: capRetry, desc: "retry without limit"},
			{name: "interval", optionCaps: capRetry, desc: "retry or fork-redial interval", aliases: []string{"intervall"}, validate: validateDurationOption},
		}},
		{"Security filters", []helpOpt{
			{name: "range", optionCaps: capRange, desc: "accept only peers in this network"},
			{name: "sourceport", optionCaps: capIPApp, desc: "peer source port (listen) or bind port (connect); DATAGRAM dest-port receive filter", aliases: []string{"sp"}},
			{name: "lowport", optionCaps: capIPApp, desc: "require or bind a low source port"},
			{name: "tcpwrap", optionCaps: capRange, desc: "apply hosts.allow / hosts.deny", aliases: []string{"tcpwrappers", "tcpwrapper", "libwrap", "wrap"}},
			{name: "tcpwrap-etc", optionCaps: capRange, desc: "directory of hosts.allow / hosts.deny", aliases: []string{"tcpwrap-dir"}},
			{name: "hosts-allow", optionCaps: capRange, desc: "allow table path", aliases: []string{"allow-table", "tcpwrap-hosts-allow-table"}},
			{name: "hosts-deny", optionCaps: capRange, desc: "deny table path", aliases: []string{"deny-table", "tcpwrap-hosts-deny-table"}},
		}},
	}
}

// Transfer options.
func transferOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Transfer", []helpOpt{
			{name: "cr", unrestricted: true, desc: "convert NL to/from CR", validate: validateNoValue},
			{name: "crnl", unrestricted: true, desc: "convert CR/NL", aliases: []string{"crlf"}, validate: validateNoValue},
			{name: "crorlf", unrestricted: true, desc: "convert CR or LF"},
			{name: "ignoreeof", unrestricted: true, desc: "do not close on EOF", aliases: []string{"ignoreof"}},
			{name: "null-eof", optionCaps: capSocket, desc: "treat a zero-length read as EOF"},
			{name: "readbytes", unrestricted: true, desc: "read at most N bytes", aliases: []string{"bytes"}, validate: validateSizeT},
			{name: "lockfile", unrestricted: true, desc: "create lock file or fail if it exists (like -L)", validate: validateRequiredString},
			{name: "waitlock", unrestricted: true, desc: "wait until lock file is gone, then create it (1s poll; CLI -W uses 100ms)", validate: validateRequiredString},
		}},
	}
}
