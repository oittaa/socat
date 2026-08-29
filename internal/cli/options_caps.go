package cli

import "github.com/oittaa/socat/internal/xio"

// Required address capabilities for helpOpt.optionCaps. Aliases inherit the
// canonical option's set in buildSupportedAddressOptions. Empty optionCaps is
// unrestricted only when helpOpt.unrestricted is set, or when addressTypes /
// help-section groups already bound the option.
var (
	capFD        = []string{xio.CapFD}
	capFIFO      = []string{xio.CapFIFO}
	capREG       = []string{xio.CapREG}
	capNamed     = []string{xio.CapNamed}
	capOpen      = []string{xio.CapOpen}
	capListen    = []string{xio.CapListen}
	capRange     = []string{xio.CapRange}
	capChild     = []string{xio.CapChild}
	capRetry     = []string{xio.CapRetry}
	capTermios   = []string{xio.CapTermios}
	capPTY       = []string{xio.CapPTY}
	capParent    = []string{xio.CapParent}
	capFork      = []string{xio.CapFork}
	capExec      = []string{xio.CapExec}
	capShell     = []string{xio.CapShell}
	capSockUNIX  = []string{xio.CapSockUNIX}
	capIP6       = []string{xio.CapSockIP6}
	capIPTCP     = []string{xio.CapIPTCP}
	capSCTP      = []string{xio.CapIPSCTP}
	capOpenSSL   = []string{xio.CapOpenSSL}
	capHTTP      = []string{xio.CapHTTP}
	capSocks     = []string{xio.CapSocks}
	capInterface = []string{xio.CapInterface}
	capPOSIXMQ   = []string{xio.CapPOSIXMQ}
	capSocket    = []string{xio.CapSocket}
	capOpenFD    = []string{xio.CapOpen, xio.CapFD}
	capFDNamed   = []string{xio.CapFD, xio.CapNamed}
	capRegBlk    = []string{xio.CapREG, xio.CapBLK}
	capIP4IP6    = []string{xio.CapSockIP4, xio.CapSockIP6}
	capIPApp     = []string{xio.CapIPUDP, xio.CapIPTCP, xio.CapIPSCTP}
)
