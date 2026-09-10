package optionmeta

import "slices"

var tlsAddressTypes = slices.Concat(dtlsAddressTypes, []string{
	"TLS", "TLS-CONNECT", "TLS-LISTEN", "TLS-L",
	"OPENSSL", "OPENSSL-CONNECT", "OPENSSL-LISTEN", "OPENSSL-L",
	"SSL", "SSL-CONNECT", "SSL-LISTEN", "SSL-L",
	"WSS", "WSS-CONNECT", "WSS-LISTEN", "WSS-L",
	"QUIC", "QUIC-CONNECT", "QUIC-LISTEN", "QUIC-L",
	"PROXY", "PROXY-CONNECT",
})

var dtlsAddressTypes = []string{"OPENSSL-DTLS-CLIENT", "OPENSSL-DTLS-SERVER",
	"DTLS", "DTLS-C", "DTLS-CLIENT", "DTLS-CONNECT", "OPENSSL-DTLS-CONNECT",
	"DTLS-L", "DTLS-LISTEN", "DTLS-SERVER", "OPENSSL-DTLS-LISTEN"}

var alpnAddressTypes = slices.Concat(dtlsAddressTypes, []string{
	"QUIC", "QUIC-CONNECT", "QUIC-LISTEN", "QUIC-L",
	"PROXY", "PROXY-CONNECT",
})

var proxyAddressTypes = []string{"PROXY", "PROXY-CONNECT"}

var socksAddressTypes = []string{
	"SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS5-CONNECT", "SOCKS5-LISTEN", "SOCKS5-BIND",
}

var handshakeAddressTypes = slices.Concat(tlsAddressTypes, []string{"WS", "WS-CONNECT", "WS-LISTEN", "WS-L"}, socksAddressTypes)

var fdOptionAddressTypes = []string{
	"STDIO", "STDIN", "STDOUT", "STDERR", "FD",
	"OPEN", "FILE", "CREATE", "CREAT", "GOPEN",
	"PIPE", "FIFO", "ECHO", "EXEC", "SYSTEM", "SHELL",
}

var backlogListenAddressTypes = []string{
	"TCP-LISTEN", "TCP-L", "TCP4-LISTEN", "TCP4-L", "TCP6-LISTEN", "TCP6-L",
	"UNIX-LISTEN", "UNIX-L",
	"ABSTRACT-LISTEN", "ABSTRACT-L",
	"TLS-LISTEN", "TLS-L",
	"OPENSSL-LISTEN", "OPENSSL-L",
	"SSL-LISTEN", "SSL-L",
	"WS-LISTEN", "WS-L",
	"WSS-LISTEN", "WSS-L",
	"SOCKET-LISTEN",
	"SCTP-LISTEN", "SCTP-L", "SCTP4-LISTEN", "SCTP4-L", "SCTP6-LISTEN", "SCTP6-L",
	"VSOCK-LISTEN", "VSOCK-L",
}

var tcpStreamAddressTypes = []string{
	"TCP", "TCP-CONNECT", "TCP4", "TCP4-CONNECT", "TCP6", "TCP6-CONNECT",
	"TCP-LISTEN", "TCP-L", "TCP4-LISTEN", "TCP4-L", "TCP6-LISTEN", "TCP6-L",
	"TLS", "TLS-CONNECT", "TLS-LISTEN", "TLS-L",
	"OPENSSL", "OPENSSL-CONNECT", "OPENSSL-LISTEN", "OPENSSL-L",
	"SSL", "SSL-CONNECT", "SSL-LISTEN", "SSL-L",
	"WS", "WS-CONNECT", "WS-LISTEN", "WS-L",
	"WSS", "WSS-CONNECT", "WSS-LISTEN", "WSS-L",
	"PROXY", "PROXY-CONNECT",
	"SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS5-CONNECT", "SOCKS5-LISTEN", "SOCKS5-BIND",
}

var tlsGroups = []string{GroupTLS, GroupDTLS, GroupWebSocket, GroupQUIC, GroupProxy}

var resolverGroups = []string{GroupTCP, GroupUDP, GroupRawIP, GroupTLS, GroupDTLS, GroupProxy, GroupWebSocket, GroupQUIC, GroupSCTP}

var socketTimeoutGroups = []string{GroupTCP, GroupUDP, GroupRawIP, GroupUnix, GroupSocket, GroupTLS, GroupDTLS, GroupProxy, GroupSCTP, GroupVSOCK}

var tcpStreamScope = AddressScope{Caps: capIPTCP, AddressTypes: tcpStreamAddressTypes}

var tlsScope = AddressScope{Caps: capOpenSSL, AddressTypes: tlsAddressTypes}

var hiddenTLSScope = AddressScope{Caps: capOpenSSL, AddressGroups: tlsGroups}

var proxyScope = AddressScope{Caps: capHTTP, AddressTypes: proxyAddressTypes}

var socksScope = AddressScope{Caps: capSocks, AddressTypes: socksAddressTypes}

var resolverScope = AddressScope{Caps: capIP4IP6, AddressGroups: resolverGroups, ImplGroups: resolverGroups}

var socketTimeoutScope = AddressScope{Caps: capSocket, AddressGroups: socketTimeoutGroups}
