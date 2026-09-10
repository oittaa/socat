package optionmeta

var webSocketOptions = []Option{
	{Canonical: "path",
		Desc:  "WebSocket URL path",
		Scope: AddressScope{Caps: capExec, AddressGroups: []string{GroupWebSocket}},
	},
	{Canonical: "origin",
		Desc:  "WebSocket Origin header",
		Scope: AddressScope{AddressGroups: []string{GroupWebSocket}},
	},
	{Canonical: "protocol",
		Desc:  "WebSocket subprotocol; VSOCK or SOCKET-* protocol number",
		Scope: AddressScope{Caps: capSocket, AddressGroups: []string{GroupWebSocket}, ImplGroups: []string{GroupWebSocket, GroupVSOCK, GroupSocket}},
	},
}
