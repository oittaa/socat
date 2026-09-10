package optionmeta

// Help section titles. Display grouping only; applicability uses Apply.
const (
	SectionListen     = "Listen and connect"
	SectionSecurity   = "Security filters"
	SectionSockets    = "Sockets"
	SectionFiles      = "Files and UNIX"
	SectionExec       = "EXEC, SYSTEM, SHELL"
	SectionPTY        = "PTY and TERMIOS"
	SectionTransfer   = "Transfer"
	SectionTLS        = "TLS, DTLS, WSS, and QUIC"
	SectionDTLS       = "Datagram TLS"
	SectionWebSocket  = "WebSocket"
	SectionProxy      = "PROXY and SOCKS"
	SectionPOSIXMQ    = "POSIX message queues"
	SectionTUN        = "TUN and INTERFACE"
	SectionNamespaces = "Namespaces"
)

// HelpSectionOrder is -hh/-hhh section order.
func HelpSectionOrder() []string {
	return []string{
		SectionListen, SectionSecurity, SectionSockets, SectionFiles,
		SectionExec, SectionPTY, SectionTransfer, SectionTLS, SectionDTLS,
		SectionWebSocket, SectionProxy, SectionPOSIXMQ, SectionTUN,
		SectionNamespaces,
	}
}

// Address capability tokens. Values match xio.Cap*.
var (
	CapFD        = []string{"fd"}
	CapFIFO      = []string{"fifo"}
	CapREG       = []string{"reg"}
	CapNamed     = []string{"named"}
	CapOpen      = []string{"open"}
	CapListen    = []string{"listen"}
	CapRange     = []string{"range"}
	CapChild     = []string{"child"}
	CapRetry     = []string{"retry"}
	CapTermios   = []string{"termios"}
	CapPTY       = []string{"pty"}
	CapParent    = []string{"parent"}
	CapFork      = []string{"fork"}
	CapExec      = []string{"exec"}
	CapShell     = []string{"shell"}
	CapSockUNIX  = []string{"sock-unix"}
	CapIP6       = []string{"sock-ip6"}
	CapIPTCP     = []string{"ip-tcp"}
	CapSCTP      = []string{"ip-sctp"}
	CapOpenSSL   = []string{"openssl"}
	CapHTTP      = []string{"http"}
	CapSocks     = []string{"socks"}
	CapInterface = []string{"interface"}
	CapPOSIXMQ   = []string{"posixmq"}
	CapSocket    = []string{"socket"}
	CapOpenFD    = []string{"open", "fd"}
	CapFDNamed   = []string{"fd", "named"}
	CapRegBlk    = []string{"reg", "blk"}
	CapIP4IP6    = []string{"sock-ip4", "sock-ip6"}
	CapIPApp     = []string{"ip-udp", "ip-tcp", "ip-sctp"}
)

// Address help-section groups. Values match xio.Group*.
const (
	GroupFiles     = "Files and stdio"
	GroupTCP       = "TCP"
	GroupUDP       = "UDP"
	GroupRawIP     = "Raw IP"
	GroupUnix      = "UNIX and abstract"
	GroupSocket    = "Generic socket"
	GroupProcess   = "Process"
	GroupDTLS      = "Datagram TLS 1.3"
	GroupTLS       = "TLS (OPENSSL/SSL aliases)"
	GroupProxy     = "PROXY and SOCKS"
	GroupTUN       = "Linux TUN / INTERFACE"
	GroupWebSocket = "WebSocket (Go extra)" // #nosec G101 -- help section title, not a secret
	GroupQUIC      = "QUIC (Go extra, not HTTP/3)"
	GroupSCTP      = "SCTP (Linux)"
	GroupVSOCK     = "VSOCK (Linux)"
	GroupPOSIXMQ   = "POSIX message queues (Linux)"
)

func tlsAddressGroups() []string {
	return []string{GroupTLS, GroupDTLS, GroupWebSocket, GroupQUIC, GroupProxy}
}

// Named extra address-type lists expanded by the CLI.
const (
	TypesTLS           = "tls"
	TypesDTLS          = "dtls"
	TypesALPN          = "alpn"
	TypesWS            = "ws"
	TypesProxy         = "proxy"
	TypesSocks         = "socks"
	TypesHandshake     = "handshake"
	TypesFD            = "fd"
	TypesBacklog       = "backlog-listen"
	TypesResolver      = "resolver"
	TypesSocketTimeout = "socket-timeout"
	TypesTCPStream     = "tcp-stream"
)

// Named implementation-group lists expanded by the CLI or xio.
const (
	ImplResolver  = "resolver"
	ImplAncillary = "ancillary"
)
