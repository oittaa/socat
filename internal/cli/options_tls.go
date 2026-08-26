package cli

// TLS, WebSocket, PROXY, and SOCKS options.
func tlsOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"TLS, WSS, and QUIC", []helpOpt{
			{name: "cert", desc: "certificate file (PEM); required on listen", addressTypes: tlsAddressTypes()},
			{name: "key", desc: "private key file (PEM)", addressTypes: tlsAddressTypes()},
			{name: "cafile", desc: "CA file (PEM or DER)", aliases: []string{"ca"}, addressTypes: tlsAddressTypes()},
			{name: "capath", desc: "directory of CA certificates", aliases: []string{"tls-capath", "openssl-capath"}, addressTypes: tlsAddressTypes()},
			{name: "verify", desc: "verify the peer (default on; 0 skips)", addressTypes: tlsAddressTypes()},
			{name: "commonname", desc: "name to check (empty skips the name check)", aliases: []string{"tls-commonname", "openssl-commonname"}, addressTypes: tlsAddressTypes()},
			{name: "snihost", desc: "TLS SNI host name", aliases: []string{"tls-snihost", "openssl-snihost"}, addressTypes: tlsAddressTypes()},
			{name: "nosni", desc: "do not send SNI", aliases: []string{"tls-no-sni", "openssl-no-sni"}, addressTypes: tlsAddressTypes()},
			{name: "ciphers", desc: "TLS 1.2 cipher suite list", aliases: []string{"cipher", "openssl-cipherlist"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-min-proto-version", desc: "minimum TLS protocol version", aliases: []string{"min-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-max-proto-version", desc: "maximum TLS protocol version", aliases: []string{"max-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "alpn", desc: "QUIC or HTTP/2/3 proxy ALPN", addressTypes: alpnAddressTypes()},
		}},
		{"WebSocket", []helpOpt{
			{name: "path", desc: "WebSocket URL path"},
			{name: "origin", desc: "WebSocket Origin header"},
			{name: "protocol", desc: "WebSocket subprotocol"},
		}},
		{"PROXY and SOCKS", []helpOpt{
			{name: "proxyport", desc: "HTTP proxy port", addressTypes: proxyAddressTypes()},
			{name: "http-version", desc: "CONNECT HTTP version (1.0, 1.1, 2, 3)", addressTypes: proxyAddressTypes()},
			{name: "h2c", desc: "cleartext HTTP/2 CONNECT", addressTypes: proxyAddressTypes()},
			{name: "proxy-resolve", desc: "resolve CONNECT target locally", aliases: []string{"resolve"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization", desc: "proxy basic auth user:pass", aliases: []string{"proxyauth"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization-file", desc: "read proxy auth from a file", aliases: []string{"proxyauthfile"}, addressTypes: proxyAddressTypes()},
			{name: "socksport", desc: "SOCKS server port", addressTypes: socksAddressTypes()},
			{name: "socksuser", desc: "SOCKS user name", addressTypes: socksAddressTypes()},
			{name: "sockspass", desc: "SOCKS password", aliases: []string{"sockspassword"}, addressTypes: socksAddressTypes()},
		}},
	}
}
