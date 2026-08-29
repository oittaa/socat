package xio

// Address capability tokens used for option-scope intersection.
// optionRequiredCaps refers to the same tokens.
const (
	CapFD        = "fd"
	CapFIFO      = "fifo"
	CapCHR       = "chr"
	CapBLK       = "blk"
	CapREG       = "reg"
	CapSocket    = "socket"
	CapNamed     = "named"
	CapOpen      = OptCapOpen
	CapListen    = OptCapListen
	CapRange     = OptCapRange
	CapChild     = "child"
	CapRetry     = "retry"
	CapTermios   = "termios"
	CapPTY       = "pty"
	CapParent    = "parent"
	CapFork      = "fork"
	CapExec      = "exec"
	CapShell     = "shell"
	CapSockUNIX  = "sock-unix"
	CapSockIP4   = "sock-ip4"
	CapSockIP6   = "sock-ip6"
	CapIPTCP     = "ip-tcp"
	CapIPUDP     = "ip-udp"
	CapIPSCTP    = "ip-sctp"
	CapIPDCCP    = "ip-dccp"
	CapIPUDPLite = "ip-udplite"
	CapOpenSSL   = "openssl"
	CapHTTP      = "http"
	CapSocks     = "socks"
	CapInterface = "interface"
	CapPOSIXMQ   = "posixmq"
)

func capset(names ...string) []string {
	return uniqueCaps(names)
}

// Reusable address capability sets. RegisterAddress assigns one of these
// (or a deliberate one-off) instead of inferring groups from the address name.
var (
	CapsFD = capset(CapFD, CapFIFO, CapCHR, CapBLK, CapREG, CapSocket, CapTermios,
		CapSockUNIX, CapSockIP4, CapSockIP6, CapIPUDP, CapIPTCP, CapIPSCTP, CapIPDCCP, CapIPUDPLite)
	CapsAcceptFD = capset(CapFD, CapSocket, CapSockUNIX, CapSockIP4, CapSockIP6,
		CapIPUDP, CapIPTCP, CapIPSCTP, CapIPDCCP, CapIPUDPLite, CapChild, CapRange, CapRetry)
	CapsPIPE   = capset(CapFD, CapNamed, CapOpen, CapFIFO)
	CapsOpen   = capset(CapFD, CapFIFO, CapCHR, CapBLK, CapREG, CapNamed, CapOpen, CapTermios)
	CapsCreate = capset(CapFD, CapNamed, CapREG)
	CapsGOPEN  = capset(CapFD, CapFIFO, CapCHR, CapBLK, CapREG, CapNamed, CapOpen, CapTermios, CapSocket, CapSockUNIX)
	CapsText   = capset(CapFD, CapFIFO)
	CapsPTY    = capset(CapNamed, CapFD, CapTermios, CapPTY)
	CapsExec   = capset(CapFD, CapFork, CapExec, CapSocket, CapSockUNIX, CapTermios, CapFIFO, CapPTY, CapParent)
	CapsSHELL  = capset(CapFD, CapFork, CapExec, CapSocket, CapSockUNIX, CapTermios, CapFIFO, CapPTY, CapParent, CapShell)

	CapsTCPConnect  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPTCP, CapChild, CapRetry)
	CapsTCPListen   = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPTCP, CapListen, CapChild, CapRange, CapRetry)
	CapsTCP4Connect = capset(CapFD, CapSocket, CapSockIP4, CapIPTCP, CapChild, CapRetry)
	CapsTCP4Listen  = capset(CapFD, CapSocket, CapSockIP4, CapIPTCP, CapListen, CapChild, CapRange, CapRetry)
	CapsTCP6Connect = capset(CapFD, CapSocket, CapSockIP6, CapIPTCP, CapChild, CapRetry)
	CapsTCP6Listen  = capset(CapFD, CapSocket, CapSockIP6, CapIPTCP, CapListen, CapChild, CapRange, CapRetry)

	CapsUDPConnect   = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPUDP)
	CapsUDPListen    = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPUDP, CapListen, CapChild, CapRange)
	CapsUDPDatagram  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPUDP, CapRange)
	CapsUDPRecvfrom  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPUDP, CapChild, CapRange)
	CapsUDP4Connect  = capset(CapFD, CapSocket, CapSockIP4, CapIPUDP)
	CapsUDP4Listen   = capset(CapFD, CapSocket, CapSockIP4, CapIPUDP, CapListen, CapChild, CapRange)
	CapsUDP4Datagram = capset(CapFD, CapSocket, CapSockIP4, CapIPUDP, CapRange)
	CapsUDP4Recvfrom = capset(CapFD, CapSocket, CapSockIP4, CapIPUDP, CapChild, CapRange)
	CapsUDP6Connect  = capset(CapFD, CapSocket, CapSockIP6, CapIPUDP)
	CapsUDP6Listen   = capset(CapFD, CapSocket, CapSockIP6, CapIPUDP, CapListen, CapChild, CapRange)
	CapsUDP6Datagram = capset(CapFD, CapSocket, CapSockIP6, CapIPUDP, CapRange)
	CapsUDP6Recvfrom = capset(CapFD, CapSocket, CapSockIP6, CapIPUDP, CapChild, CapRange)

	CapsIPSendto    = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6)
	CapsIPDatagram  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapRange)
	CapsIPRecvfrom  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapChild, CapRange)
	CapsIP4Sendto   = capset(CapFD, CapSocket, CapSockIP4)
	CapsIP4Datagram = capset(CapFD, CapSocket, CapSockIP4, CapRange)
	CapsIP4Recvfrom = capset(CapFD, CapSocket, CapSockIP4, CapChild, CapRange)
	CapsIP6Sendto   = capset(CapFD, CapSocket, CapSockIP6)
	CapsIP6Datagram = capset(CapFD, CapSocket, CapSockIP6, CapRange)
	CapsIP6Recvfrom = capset(CapFD, CapSocket, CapSockIP6, CapChild, CapRange)

	CapsUNIXConnect      = capset(CapFD, CapNamed, CapSocket, CapSockUNIX, CapRetry)
	CapsUNIXListen       = capset(CapFD, CapNamed, CapSocket, CapSockUNIX, CapListen, CapChild, CapRetry)
	CapsUNIXRecvfrom     = capset(CapFD, CapNamed, CapSocket, CapSockUNIX, CapRetry, CapChild)
	CapsAbstract         = capset(CapFD, CapSocket, CapSockUNIX, CapRetry)
	CapsAbstractListen   = capset(CapFD, CapSocket, CapSockUNIX, CapListen, CapChild, CapRetry)
	CapsAbstractRecvfrom = capset(CapFD, CapSocket, CapSockUNIX, CapRetry, CapChild)

	CapsSocketConnect  = capset(CapFD, CapSocket, CapChild, CapRetry)
	CapsSocketListen   = capset(CapFD, CapSocket, CapListen, CapRange, CapChild, CapRetry)
	CapsSocketDatagram = capset(CapFD, CapSocket, CapRange)
	CapsSocketSendto   = capset(CapFD, CapSocket)
	CapsSocketRecvfrom = capset(CapFD, CapSocket, CapRange, CapChild)

	CapsSCTPConnect  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPSCTP, CapChild, CapRetry)
	CapsSCTPListen   = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPSCTP, CapListen, CapChild, CapRange, CapRetry)
	CapsSCTP4Connect = capset(CapFD, CapSocket, CapSockIP4, CapIPSCTP, CapChild, CapRetry)
	CapsSCTP4Listen  = capset(CapFD, CapSocket, CapSockIP4, CapIPSCTP, CapListen, CapChild, CapRange, CapRetry)
	CapsSCTP6Connect = capset(CapFD, CapSocket, CapSockIP6, CapIPSCTP, CapChild, CapRetry)
	CapsSCTP6Listen  = capset(CapFD, CapSocket, CapSockIP6, CapIPSCTP, CapListen, CapChild, CapRange, CapRetry)

	CapsVSOCKConnect = capset(CapFD, CapSocket, CapChild, CapRetry)
	CapsVSOCKListen  = capset(CapFD, CapSocket, CapListen, CapChild, CapRetry)

	CapsTLSConnect  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPTCP, CapChild, CapOpenSSL, CapRetry)
	CapsTLSListen   = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPTCP, CapListen, CapChild, CapRange, CapOpenSSL, CapRetry)
	CapsQUICConnect = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPUDP, CapChild, CapOpenSSL, CapRetry)
	CapsQUICListen  = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPUDP, CapListen, CapChild, CapRange, CapOpenSSL, CapRetry)

	CapsProxy = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPTCP, CapHTTP, CapChild, CapRetry)
	CapsSocks = capset(CapFD, CapSocket, CapSockIP4, CapSockIP6, CapIPTCP, CapSocks, CapChild, CapRetry)

	CapsTUN       = capset(CapFD, CapCHR, CapOpen, CapInterface)
	CapsINTERFACE = capset(CapFD, CapSocket, CapInterface)

	CapsPOSIXMQ      = capset(CapFD, CapOpen, CapNamed, CapPOSIXMQ, CapRetry)
	CapsPOSIXMQChild = capset(CapFD, CapOpen, CapNamed, CapPOSIXMQ, CapRetry, CapChild)
)
