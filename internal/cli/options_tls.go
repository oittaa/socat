package cli

import "github.com/oittaa/socat/internal/xio"

// TLS, WebSocket, PROXY, and SOCKS options.
func tlsOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"TLS, DTLS, WSS, and QUIC", []helpOpt{
			{name: "cert", optionCaps: capOpenSSL, desc: "certificate file (PEM); required on listen", aliases: []string{"certificate", "openssl-certificate"}, addressTypes: tlsAddressTypes()},
			{name: "key", optionCaps: capOpenSSL, desc: "private key file (PEM)", aliases: []string{"openssl-key"}, addressTypes: tlsAddressTypes()},
			{name: "cafile", optionCaps: capOpenSSL, desc: "CA file (PEM or DER)", aliases: []string{"ca", "openssl-cafile"}, addressTypes: tlsAddressTypes()},
			{name: "capath", optionCaps: capOpenSSL, desc: "directory of CA certificates", aliases: []string{"tls-capath", "openssl-capath"}, addressTypes: tlsAddressTypes()},
			{name: "verify", optionCaps: capOpenSSL, desc: "verify the peer (default on; 0 skips)", aliases: []string{"openssl-verify"}, addressTypes: tlsAddressTypes()},
			{name: "commonname", optionCaps: capOpenSSL, desc: "name to check (empty skips the name check)", aliases: []string{"cn", "tls-commonname", "openssl-commonname"}, addressTypes: tlsAddressTypes()},
			{name: "snihost", optionCaps: capOpenSSL, desc: "TLS SNI host name", aliases: []string{"tls-snihost", "openssl-snihost"}, addressTypes: tlsAddressTypes()},
			{name: "nosni", optionCaps: capOpenSSL, desc: "do not send SNI", aliases: []string{"no-sni", "tls-no-sni", "openssl-no-sni"}, addressTypes: tlsAddressTypes()},
			{name: "ciphers", optionCaps: capOpenSSL, desc: "TLS 1.2 cipher suite list", aliases: []string{"cipher", "cipherlist", "openssl-cipherlist"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-compress", optionCaps: capOpenSSL, desc: "TLS compression policy (only none is supported)", aliases: []string{"compress"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-min-proto-version", optionCaps: capOpenSSL, desc: "minimum TLS or DTLS protocol version", aliases: []string{"min-proto-version", "min-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "openssl-max-proto-version", optionCaps: capOpenSSL, desc: "maximum TLS or DTLS protocol version", aliases: []string{"max-proto-version", "max-version"}, addressTypes: tlsAddressTypes(), validate: validateRequiredString},
			{name: "alpn", desc: "DTLS, QUIC, or HTTP/2/3 proxy ALPN", addressTypes: alpnAddressTypes()},
		}},
		{"Datagram TLS", []helpOpt{
			{name: "dtls-mtu", desc: "maximum UDP payload in bytes (256..65507, default 1200)", addressTypes: dtlsAddressTypes(), validate: validateIntegerRange(256, 65507)},
			{name: "dtls-migration", desc: "negotiate connection IDs and validated address migration (default on)", addressTypes: dtlsAddressTypes(), validate: validateOptionalBool},
		}},
		{"WebSocket", []helpOpt{
			{name: "path", optionCaps: capExec, desc: "WebSocket URL path"},
			{name: "origin", desc: "WebSocket Origin header"},
			{name: "protocol", optionCaps: capSocket, desc: "WebSocket subprotocol; VSOCK or SOCKET-* socket() protocol number", implementationGroups: []string{xio.GroupWebSocket, xio.GroupVSOCK, xio.GroupSocket}},
		}},
		{"PROXY and SOCKS", []helpOpt{
			{name: "proxyport", optionCaps: capHTTP, desc: "HTTP proxy port", addressTypes: proxyAddressTypes()},
			{name: "http-version", optionCaps: capHTTP, desc: "CONNECT HTTP version (1.0, 1.1, 2, 3)", addressTypes: proxyAddressTypes()},
			{name: "h2c", desc: "cleartext HTTP/2 CONNECT", addressTypes: proxyAddressTypes()},
			{name: "ignorecr", optionCaps: capHTTP, desc: "accept LF as HTTP CONNECT response line terminator", addressTypes: proxyAddressTypes(), validate: validateOptionalBool},
			{name: "proxy-resolve", optionCaps: capHTTP, desc: "resolve CONNECT target locally", aliases: []string{"resolve", "resolv"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization", optionCaps: capHTTP, desc: "proxy basic auth user:pass", aliases: []string{"proxyauth", "proxy-auth"}, addressTypes: proxyAddressTypes()},
			{name: "proxy-authorization-file", optionCaps: capHTTP, desc: "read proxy auth from a file", aliases: []string{"proxyauthfile"}, addressTypes: proxyAddressTypes()},
			{name: "socksport", optionCaps: capSocks, desc: "SOCKS server port", addressTypes: socksAddressTypes()},
			{name: "socksuser", optionCaps: capSocks, desc: "SOCKS user name", addressTypes: socksAddressTypes()},
			{name: "sockspass", optionCaps: capSocks, desc: "SOCKS password", aliases: []string{"sockspassword"}, addressTypes: socksAddressTypes()},
		}},
	}
}
