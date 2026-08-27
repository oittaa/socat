package cli

import "github.com/oittaa/socat/internal/xio"

// TLS, WebSocket, PROXY, and SOCKS options.
func tlsOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"TLS, WSS, and QUIC", []helpOpt{
			{name: "cert", desc: "certificate file (PEM); required on listen", aliases: []string{"certificate", "openssl-certificate"}, addressTypes: tlsAddressTypes()},
			{name: "key", desc: "private key file (PEM)", aliases: []string{"openssl-key"}, addressTypes: tlsAddressTypes()},
			{name: "cafile", desc: "CA file (PEM or DER)", aliases: []string{"ca", "openssl-cafile"}, addressTypes: tlsAddressTypes()},
			{name: "capath", desc: "directory of CA certificates", aliases: []string{"tls-capath", "openssl-capath"}, addressTypes: tlsAddressTypes()},
			{name: "verify", desc: "verify the peer (default on; 0 skips)", aliases: []string{"openssl-verify"}, addressTypes: tlsAddressTypes()},
			{name: "commonname", desc: "name to check (empty skips the name check)", aliases: []string{"cn", "tls-commonname", "openssl-commonname"}, addressTypes: tlsAddressTypes()},
			{name: "snihost", desc: "TLS SNI host name", aliases: []string{"tls-snihost", "openssl-snihost"}, addressTypes: tlsAddressTypes()},
			{name: "nosni", desc: "do not send SNI", aliases: []string{"no-sni", "tls-no-sni", "openssl-no-sni"}, addressTypes: tlsAddressTypes()},
			{name: "ciphers", desc: "TLS 1.2 cipher suite list", aliases: []string{"cipher", "cipherlist", "openssl-cipherlist"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-compress", desc: "TLS compression policy (only none is supported)", aliases: []string{"compress"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-min-proto-version", desc: "minimum TLS protocol version", aliases: []string{"min-proto-version", "min-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-max-proto-version", desc: "maximum TLS protocol version", aliases: []string{"max-proto-version", "max-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "alpn", desc: "QUIC or HTTP/2/3 proxy ALPN", addressTypes: alpnAddressTypes()},
		}},
		{"WebSocket", []helpOpt{
			{name: "path", desc: "WebSocket URL path"},
			{name: "origin", desc: "WebSocket Origin header"},
			{name: "protocol", desc: "WebSocket subprotocol; VSOCK socket() protocol number", implementationGroups: []string{xio.GroupWebSocket, xio.GroupVSOCK}},
		}},
		{"PROXY and SOCKS", []helpOpt{
			{name: "proxyport", desc: "HTTP proxy port", addressTypes: proxyAddressTypes()},
			{name: "http-version", desc: "CONNECT HTTP version (1.0, 1.1, 2, 3)", addressTypes: proxyAddressTypes()},
			{name: "h2c", desc: "cleartext HTTP/2 CONNECT", addressTypes: proxyAddressTypes()},
			{name: "ignorecr", desc: "accept LF as HTTP CONNECT response line terminator", addressTypes: proxyAddressTypes(), validate: validateOptionalBool},
			{name: "proxy-resolve", desc: "resolve CONNECT target locally", aliases: []string{"resolve", "resolv"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization", desc: "proxy basic auth user:pass", aliases: []string{"proxyauth", "proxy-auth"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization-file", desc: "read proxy auth from a file", aliases: []string{"proxyauthfile"}, addressTypes: proxyAddressTypes()},
			{name: "socksport", desc: "SOCKS server port", addressTypes: socksAddressTypes()},
			{name: "socksuser", desc: "SOCKS user name", addressTypes: socksAddressTypes()},
			{name: "sockspass", desc: "SOCKS password", aliases: []string{"sockspassword"}, addressTypes: socksAddressTypes()},
		}},
	}
}
