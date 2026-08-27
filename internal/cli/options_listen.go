package cli

// Listen, connect, and security-filter options.
func listenOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Listen and connect", []helpOpt{
			{name: "reuseaddr", desc: "SO_REUSEADDR (TCP listen default on; UDP-LISTEN / UDPLITE-LISTEN with fork or this option)", aliases: []string{"so-reuseaddr"}},
			{name: "reuseport", desc: "SO_REUSEPORT", aliases: []string{"so-reuseport"}},
			{name: "fork", desc: "new session per accept or client redial"},
			{name: "nofork", desc: "do not fork (single session)"},
			{name: "max-children", desc: "limit concurrent fork sessions (needs fork)", aliases: []string{"maxchildren"}, validate: validateInteger(1)},
			{name: "children-shutup", desc: "lower fork-child log severity", aliases: []string{"child-shutup"}, validate: validateOptionalInteger(0)},
			{name: "bind", desc: "local address or interface"},
			{name: "connect-timeout", desc: "connect timeout", validate: validateDurationOption},
			{name: "handshake-timeout", desc: "TLS, WebSocket, QUIC, PROXY, or SOCKS handshake timeout", addressTypes: handshakeAddressTypes(), validate: validateDurationOption},
			{name: "accept-timeout", desc: "listen accept timeout (exit 0)", aliases: []string{"listen-timeout"}, validate: validateDurationOption},
			{name: "backlog", desc: "listen backlog", addressTypes: []string{
				"TCP-LISTEN", "TCP-L", "TCP4-LISTEN", "TCP4-L", "TCP6-LISTEN", "TCP6-L",
				"SOCKET-LISTEN", "SCTP-LISTEN", "SCTP-L", "SCTP4-LISTEN", "SCTP4-L", "SCTP6-LISTEN", "SCTP6-L",
				"VSOCK-LISTEN", "VSOCK-L",
			}, validate: validateInteger(1)},
			{name: "pf", desc: "address family (4, 6, IP4, IP6, …)", aliases: []string{"protocol-family"}},
			{name: "ai-addrconfig", desc: "getaddrinfo AI_ADDRCONFIG", aliases: []string{"addrconfig"}},
			{name: "ipv6-v6only", desc: "IPV6_V6ONLY", aliases: []string{"ipv6only", "v6only"}},
			{name: "retry", desc: "retry count on connect failure", validate: validateInteger(-1)},
			{name: "forever", desc: "retry without limit"},
			{name: "interval", desc: "retry or fork-redial interval", aliases: []string{"intervall"}, validate: validateDurationOption},
		}},
		{"Security filters", []helpOpt{
			{name: "range", desc: "accept only peers in this network"},
			{name: "sourceport", desc: "peer source port (listen) or bind port (connect)", aliases: []string{"sp"}},
			{name: "lowport", desc: "require or bind a low source port"},
			{name: "tcpwrap", desc: "apply hosts.allow / hosts.deny", aliases: []string{"tcpwrappers", "tcpwrapper", "libwrap", "wrap"}},
			{name: "tcpwrap-etc", desc: "directory of hosts.allow / hosts.deny", aliases: []string{"tcpwrap-dir"}},
			{name: "hosts-allow", desc: "allow table path", aliases: []string{"allow-table", "tcpwrap-hosts-allow-table"}},
			{name: "hosts-deny", desc: "deny table path", aliases: []string{"deny-table", "tcpwrap-hosts-deny-table"}},
		}},
	}
}

// Transfer options.
func transferOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Transfer", []helpOpt{
			{name: "crnl", desc: "convert CR/NL", aliases: []string{"crlf"}},
			{name: "crorlf", desc: "convert CR or LF"},
			{name: "ignoreeof", desc: "do not close on EOF", aliases: []string{"ignoreof"}},
			{name: "null-eof", desc: "treat a zero-length read as EOF"},
			{name: "readbytes", desc: "read at most N bytes", aliases: []string{"bytes"}, validate: validateSizeT},
		}},
	}
}
