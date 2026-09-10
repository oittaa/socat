package optionmeta

// Help section titles. Display grouping only; address validation uses Scope.
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

// Option capability sets.
var (
	capFD        = []string{CapFD}
	capFIFO      = []string{CapFIFO}
	capREG       = []string{CapREG}
	capNamed     = []string{CapNamed}
	capOpen      = []string{CapOpen}
	capListen    = []string{CapListen}
	capRange     = []string{CapRange}
	capChild     = []string{CapChild}
	capRetry     = []string{CapRetry}
	capTermios   = []string{CapTermios}
	capPTY       = []string{CapPTY}
	capParent    = []string{CapParent}
	capFork      = []string{CapFork}
	capExec      = []string{CapExec}
	capShell     = []string{CapShell}
	capSockUNIX  = []string{CapSockUNIX}
	capIP6       = []string{CapSockIP6}
	capIPTCP     = []string{CapIPTCP}
	capSCTP      = []string{CapIPSCTP}
	capOpenSSL   = []string{CapOpenSSL}
	capHTTP      = []string{CapHTTP}
	capSocks     = []string{CapSocks}
	capInterface = []string{CapInterface}
	capPOSIXMQ   = []string{CapPOSIXMQ}
	capSocket    = []string{CapSocket}
	capOpenFD    = []string{CapOpen, CapFD}
	capFDNamed   = []string{CapFD, CapNamed}
	capRegBlk    = []string{CapREG, CapBLK}
	capIP4IP6    = []string{CapSockIP4, CapSockIP6}
	capIPApp     = []string{CapIPUDP, CapIPTCP, CapIPSCTP}
)

// Address groups shared by registrations and option applicability.
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
