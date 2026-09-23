package xio

import "github.com/oittaa/socat/internal/optionmeta"

// Address capability tokens used for option-scope intersection.
const (
	capFD        = optionmeta.CapFD
	capFIFO      = optionmeta.CapFIFO
	capCHR       = optionmeta.CapCHR
	capBLK       = optionmeta.CapBLK
	capREG       = optionmeta.CapREG
	capSocket    = optionmeta.CapSocket
	capNamed     = optionmeta.CapNamed
	capOpen      = optionmeta.CapOpen
	capListen    = optionmeta.CapListen
	capRange     = optionmeta.CapRange
	capChild     = optionmeta.CapChild
	capRetry     = optionmeta.CapRetry
	capTermios   = optionmeta.CapTermios
	capPTY       = optionmeta.CapPTY
	capParent    = optionmeta.CapParent
	capFork      = optionmeta.CapFork
	capExec      = optionmeta.CapExec
	capShell     = optionmeta.CapShell
	capSockUNIX  = optionmeta.CapSockUNIX
	capSockIP4   = optionmeta.CapSockIP4
	capSockIP6   = optionmeta.CapSockIP6
	capIPTCP     = optionmeta.CapIPTCP
	capIPUDP     = optionmeta.CapIPUDP
	capIPSCTP    = optionmeta.CapIPSCTP
	capOpenSSL   = optionmeta.CapOpenSSL
	capHTTP      = optionmeta.CapHTTP
	capSocks     = optionmeta.CapSocks
	capInterface = optionmeta.CapInterface
	capPOSIXMQ   = optionmeta.CapPOSIXMQ
)

func capset(names ...string) []string {
	return uniqueCaps(names)
}

// Reusable address capability sets. RegisterAddress assigns one of these
// (or a deliberate one-off) instead of inferring groups from the address name.
var (
	CapsFD = capset(capFD, capFIFO, capCHR, capBLK, capREG, capSocket, capTermios,
		capSockUNIX, capSockIP4, capSockIP6, capIPUDP, capIPTCP, capIPSCTP)
	CapsAcceptFD = capset(capFD, capSocket, capSockUNIX, capSockIP4, capSockIP6,
		capIPUDP, capIPTCP, capIPSCTP, capChild, capRange, capRetry)
	CapsPIPE   = capset(capFD, capNamed, capOpen, capFIFO)
	CapsOpen   = capset(capFD, capFIFO, capCHR, capBLK, capREG, capNamed, capOpen, capTermios)
	CapsCreate = capset(capFD, capNamed, capREG)
	CapsGOPEN  = capset(capFD, capFIFO, capCHR, capBLK, capREG, capNamed, capOpen, capTermios, capSocket, capSockUNIX)
	CapsText   = capset(capFD, capFIFO)
	CapsPTY    = capset(capNamed, capFD, capTermios, capPTY)
	CapsExec   = capset(capFD, capFork, capExec, capSocket, capSockUNIX, capTermios, capFIFO, capPTY, capParent)
	CapsSHELL  = capset(capFD, capFork, capExec, capSocket, capSockUNIX, capTermios, capFIFO, capPTY, capParent, capShell)

	CapsTCPConnect  = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPTCP, capChild, capRetry)
	CapsTCPListen   = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPTCP, capListen, capChild, capRange, capRetry)
	CapsTCP4Connect = capset(capFD, capSocket, capSockIP4, capIPTCP, capChild, capRetry)
	CapsTCP4Listen  = capset(capFD, capSocket, capSockIP4, capIPTCP, capListen, capChild, capRange, capRetry)
	CapsTCP6Connect = capset(capFD, capSocket, capSockIP6, capIPTCP, capChild, capRetry)
	CapsTCP6Listen  = capset(capFD, capSocket, capSockIP6, capIPTCP, capListen, capChild, capRange, capRetry)

	CapsUDPConnect   = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPUDP)
	CapsUDPListen    = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPUDP, capListen, capChild, capRange)
	CapsUDPDatagram  = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPUDP, capRange)
	CapsUDPRecvfrom  = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPUDP, capChild, capRange)
	CapsUDP4Connect  = capset(capFD, capSocket, capSockIP4, capIPUDP)
	CapsUDP4Listen   = capset(capFD, capSocket, capSockIP4, capIPUDP, capListen, capChild, capRange)
	CapsUDP4Datagram = capset(capFD, capSocket, capSockIP4, capIPUDP, capRange)
	CapsUDP4Recvfrom = capset(capFD, capSocket, capSockIP4, capIPUDP, capChild, capRange)
	CapsUDP6Connect  = capset(capFD, capSocket, capSockIP6, capIPUDP)
	CapsUDP6Listen   = capset(capFD, capSocket, capSockIP6, capIPUDP, capListen, capChild, capRange)
	CapsUDP6Datagram = capset(capFD, capSocket, capSockIP6, capIPUDP, capRange)
	CapsUDP6Recvfrom = capset(capFD, capSocket, capSockIP6, capIPUDP, capChild, capRange)

	CapsIPSendto    = capset(capFD, capSocket, capSockIP4, capSockIP6)
	CapsIPDatagram  = capset(capFD, capSocket, capSockIP4, capSockIP6, capRange)
	CapsIPRecvfrom  = capset(capFD, capSocket, capSockIP4, capSockIP6, capChild, capRange)
	CapsIP4Sendto   = capset(capFD, capSocket, capSockIP4)
	CapsIP4Datagram = capset(capFD, capSocket, capSockIP4, capRange)
	CapsIP4Recvfrom = capset(capFD, capSocket, capSockIP4, capChild, capRange)
	CapsIP6Sendto   = capset(capFD, capSocket, capSockIP6)
	CapsIP6Datagram = capset(capFD, capSocket, capSockIP6, capRange)
	CapsIP6Recvfrom = capset(capFD, capSocket, capSockIP6, capChild, capRange)

	CapsUNIXConnect      = capset(capFD, capNamed, capSocket, capSockUNIX, capRetry)
	CapsUNIXListen       = capset(capFD, capNamed, capSocket, capSockUNIX, capListen, capChild, capRetry)
	CapsUNIXRecvfrom     = capset(capFD, capNamed, capSocket, capSockUNIX, capRetry, capChild)
	CapsAbstract         = capset(capFD, capSocket, capSockUNIX, capRetry)
	CapsAbstractListen   = capset(capFD, capSocket, capSockUNIX, capListen, capChild, capRetry)
	CapsAbstractRecvfrom = capset(capFD, capSocket, capSockUNIX, capRetry, capChild)

	CapsSocketConnect  = capset(capFD, capSocket, capChild, capRetry)
	CapsSocketListen   = capset(capFD, capSocket, capListen, capRange, capChild, capRetry)
	CapsSocketDatagram = capset(capFD, capSocket, capRange)
	CapsSocketSendto   = capset(capFD, capSocket)
	CapsSocketRecvfrom = capset(capFD, capSocket, capRange, capChild)

	CapsSCTPConnect  = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPSCTP, capChild, capRetry)
	CapsSCTPListen   = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPSCTP, capListen, capChild, capRange, capRetry)
	CapsSCTP4Connect = capset(capFD, capSocket, capSockIP4, capIPSCTP, capChild, capRetry)
	CapsSCTP4Listen  = capset(capFD, capSocket, capSockIP4, capIPSCTP, capListen, capChild, capRange, capRetry)
	CapsSCTP6Connect = capset(capFD, capSocket, capSockIP6, capIPSCTP, capChild, capRetry)
	CapsSCTP6Listen  = capset(capFD, capSocket, capSockIP6, capIPSCTP, capListen, capChild, capRange, capRetry)

	CapsVSOCKConnect = capset(capFD, capSocket, capChild, capRetry)
	CapsVSOCKListen  = capset(capFD, capSocket, capListen, capChild, capRetry)

	CapsTLSConnect       = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPTCP, capChild, capOpenSSL, capRetry)
	CapsTLSListen        = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPTCP, capListen, capChild, capRange, capOpenSSL, capRetry)
	CapsSecureUDPConnect = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPUDP, capChild, capOpenSSL, capRetry)
	CapsSecureUDPListen  = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPUDP, capListen, capChild, capRange, capOpenSSL, capRetry)

	CapsProxy = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPTCP, capHTTP, capChild, capRetry)
	CapsSocks = capset(capFD, capSocket, capSockIP4, capSockIP6, capIPTCP, capSocks, capChild, capRetry)

	CapsTUN       = capset(capFD, capCHR, capOpen, capInterface)
	CapsINTERFACE = capset(capFD, capSocket, capInterface)

	CapsPOSIXMQ      = capset(capFD, capOpen, capNamed, capPOSIXMQ, capRetry)
	CapsPOSIXMQChild = capset(capFD, capOpen, capNamed, capPOSIXMQ, capRetry, capChild)
)
