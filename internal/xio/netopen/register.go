package netopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	// TCP
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP", Syntax: "TCP:<host>:<port>", Desc: "TCP client", Opener: openTCPConnect, OptionCaps: xio.CapsTCPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP-CONNECT", Syntax: "TCP-CONNECT:<host>:<port>", Desc: "same as TCP", Opener: openTCPConnect, OptionCaps: xio.CapsTCPConnect, Aliases: []string{"INET"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4", Syntax: "TCP4:<host>:<port>", Desc: "IPv4 TCP client", Opener: openTCP4Connect, OptionCaps: xio.CapsTCP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4-CONNECT", Syntax: "TCP4-CONNECT:<host>:<port>", Desc: "same as TCP4", Opener: openTCP4Connect, OptionCaps: xio.CapsTCP4Connect, Aliases: []string{"INET4"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6", Syntax: "TCP6:<host>:<port>", Desc: "IPv6 TCP client", Opener: openTCP6Connect, OptionCaps: xio.CapsTCP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6-CONNECT", Syntax: "TCP6-CONNECT:<host>:<port>", Desc: "same as TCP6", Opener: openTCP6Connect, OptionCaps: xio.CapsTCP6Connect, Aliases: []string{"INET6"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP-LISTEN", Syntax: "TCP-LISTEN:<port>", Desc: "TCP server", Opener: openTCPListen, OptionCaps: xio.CapsTCPListen, Aliases: []string{"INET-L", "INET-LISTEN"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP-L", Syntax: "TCP-L:<port>", Desc: "same as TCP-LISTEN", Opener: openTCPListen, OptionCaps: xio.CapsTCPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4-LISTEN", Syntax: "TCP4-LISTEN:<port>", Desc: "IPv4 TCP server", Opener: openTCP4Listen, OptionCaps: xio.CapsTCP4Listen, Aliases: []string{"INET4-L", "INET4-LISTEN"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4-L", Syntax: "TCP4-L:<port>", Desc: "same as TCP4-LISTEN", Opener: openTCP4Listen, OptionCaps: xio.CapsTCP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6-LISTEN", Syntax: "TCP6-LISTEN:<port>", Desc: "IPv6 TCP server", Opener: openTCP6Listen, OptionCaps: xio.CapsTCP6Listen, Aliases: []string{"INET6-L", "INET6-LISTEN"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6-L", Syntax: "TCP6-L:<port>", Desc: "same as TCP6-LISTEN", Opener: openTCP6Listen, OptionCaps: xio.CapsTCP6Listen})

	// UDP
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP", Syntax: "UDP:<host>:<port>", Desc: "UDP client", Opener: openUDPConnect, OptionCaps: xio.CapsUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-CONNECT", Syntax: "UDP-CONNECT:<host>:<port>", Desc: "same as UDP", Opener: openUDPConnect, OptionCaps: xio.CapsUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4", Syntax: "UDP4:<host>:<port>", Desc: "IPv4 UDP client", Opener: openUDP4Connect, OptionCaps: xio.CapsUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-CONNECT", Syntax: "UDP4-CONNECT:<host>:<port>", Desc: "same as UDP4", Opener: openUDP4Connect, OptionCaps: xio.CapsUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6", Syntax: "UDP6:<host>:<port>", Desc: "IPv6 UDP client", Opener: openUDP6Connect, OptionCaps: xio.CapsUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-CONNECT", Syntax: "UDP6-CONNECT:<host>:<port>", Desc: "same as UDP6", Opener: openUDP6Connect, OptionCaps: xio.CapsUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-LISTEN", Syntax: "UDP-LISTEN:<port>", Desc: "UDP server", Opener: openUDPListen, OptionCaps: xio.CapsUDPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-L", Syntax: "UDP-L:<port>", Desc: "same as UDP-LISTEN", Opener: openUDPListen, OptionCaps: xio.CapsUDPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-LISTEN", Syntax: "UDP4-LISTEN:<port>", Desc: "IPv4 UDP server", Opener: openUDP4Listen, OptionCaps: xio.CapsUDP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-L", Syntax: "UDP4-L:<port>", Desc: "same as UDP4-LISTEN", Opener: openUDP4Listen, OptionCaps: xio.CapsUDP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-LISTEN", Syntax: "UDP6-LISTEN:<port>", Desc: "IPv6 UDP server", Opener: openUDP6Listen, OptionCaps: xio.CapsUDP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-L", Syntax: "UDP6-L:<port>", Desc: "same as UDP6-LISTEN", Opener: openUDP6Listen, OptionCaps: xio.CapsUDP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-SENDTO", Syntax: "UDP-SENDTO:<host>:<port>", Desc: "UDP send to one peer", Opener: openUDPSendto, OptionCaps: xio.CapsUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-SEND", Syntax: "UDP-SEND:<host>:<port>", Desc: "same as UDP-SENDTO", Opener: openUDPSendto, OptionCaps: xio.CapsUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-SENDTO", Syntax: "UDP4-SENDTO:<host>:<port>", Desc: "IPv4 UDP send to one peer", Opener: openUDP4Sendto, OptionCaps: xio.CapsUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-SEND", Syntax: "UDP4-SEND:<host>:<port>", Desc: "same as UDP4-SENDTO", Opener: openUDP4Sendto, OptionCaps: xio.CapsUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-SENDTO", Syntax: "UDP6-SENDTO:<host>:<port>", Desc: "IPv6 UDP send to one peer", Opener: openUDP6Sendto, OptionCaps: xio.CapsUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-SEND", Syntax: "UDP6-SEND:<host>:<port>", Desc: "same as UDP6-SENDTO", Opener: openUDP6Sendto, OptionCaps: xio.CapsUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-DATAGRAM", Syntax: "UDP-DATAGRAM:<host>:<port>", Desc: "unconnected UDP datagram", Opener: openUDPDatagram, OptionCaps: xio.CapsUDPDatagram, Aliases: []string{"UDP-DGRAM"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-DATAGRAM", Syntax: "UDP4-DATAGRAM:<host>:<port>", Desc: "IPv4 UDP datagram", Opener: openUDP4Datagram, OptionCaps: xio.CapsUDP4Datagram, Aliases: []string{"UDP4-DGRAM"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-DATAGRAM", Syntax: "UDP6-DATAGRAM:<host>:<port>", Desc: "IPv6 UDP datagram", Opener: openUDP6Datagram, OptionCaps: xio.CapsUDP6Datagram, Aliases: []string{"UDP6-DGRAM"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-RECV", Syntax: "UDP-RECV:<port>", Desc: "receive UDP; ignore source", Opener: openUDPRecv, OptionCaps: xio.CapsUDPDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-RECV", Syntax: "UDP4-RECV:<port>", Desc: "IPv4 UDP receive", Opener: openUDP4Recv, OptionCaps: xio.CapsUDP4Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-RECV", Syntax: "UDP6-RECV:<port>", Desc: "IPv6 UDP receive", Opener: openUDP6Recv, OptionCaps: xio.CapsUDP6Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-RECVFROM", Syntax: "UDP-RECVFROM:<port>", Desc: "receive one UDP datagram, reply to sender", Opener: openUDPRecvfrom, OptionCaps: xio.CapsUDPRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-RECVFROM", Syntax: "UDP4-RECVFROM:<port>", Desc: "IPv4 UDP recvfrom", Opener: openUDP4Recvfrom, OptionCaps: xio.CapsUDP4Recvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-RECVFROM", Syntax: "UDP6-RECVFROM:<port>", Desc: "IPv6 UDP recvfrom", Opener: openUDP6Recvfrom, OptionCaps: xio.CapsUDP6Recvfrom})

	// Raw IP
	rawIPEnabled := func() bool { return xio.FeatureRAWIP }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP", Syntax: "IP:<host>:<protocol>", Desc: "raw IP send/receive", Enabled: rawIPEnabled, Opener: openIP, OptionCaps: xio.CapsIPSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4", Syntax: "IP4:<host>:<protocol>", Desc: "IPv4 raw IP", Enabled: rawIPEnabled, Opener: openIP4, OptionCaps: xio.CapsIP4Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6", Syntax: "IP6:<host>:<protocol>", Desc: "IPv6 raw IP", Enabled: rawIPEnabled, Opener: openIP6, OptionCaps: xio.CapsIP6Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-SENDTO", Syntax: "IP-SENDTO:<host>:<protocol>", Desc: "raw IP send to one peer", Enabled: rawIPEnabled, Opener: openIPSendto, OptionCaps: xio.CapsIPSendto, Aliases: []string{"IP-SEND"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-SENDTO", Syntax: "IP4-SENDTO:<host>:<protocol>", Desc: "IPv4 raw IP sendto", Enabled: rawIPEnabled, Opener: openIP4Sendto, OptionCaps: xio.CapsIP4Sendto, Aliases: []string{"IP4-SEND"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-SENDTO", Syntax: "IP6-SENDTO:<host>:<protocol>", Desc: "IPv6 raw IP sendto", Enabled: rawIPEnabled, Opener: openIP6Sendto, OptionCaps: xio.CapsIP6Sendto, Aliases: []string{"IP6-SEND"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-DATAGRAM", Syntax: "IP-DATAGRAM:<host>:<protocol>", Desc: "raw IP datagram", Enabled: rawIPEnabled, Opener: openIPDatagram, OptionCaps: xio.CapsIPDatagram, Aliases: []string{"IP-DGRAM"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-DATAGRAM", Syntax: "IP4-DATAGRAM:<host>:<protocol>", Desc: "IPv4 raw IP datagram", Enabled: rawIPEnabled, Opener: openIP4Datagram, OptionCaps: xio.CapsIP4Datagram, Aliases: []string{"IP4-DGRAM"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-DATAGRAM", Syntax: "IP6-DATAGRAM:<host>:<protocol>", Desc: "IPv6 raw IP datagram", Enabled: rawIPEnabled, Opener: openIP6Datagram, OptionCaps: xio.CapsIP6Datagram, Aliases: []string{"IP6-DGRAM"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-RECV", Syntax: "IP-RECV:<protocol>", Desc: "raw IP receive", Enabled: rawIPEnabled, Opener: openIPRecv, OptionCaps: xio.CapsIPDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-RECV", Syntax: "IP4-RECV:<protocol>", Desc: "IPv4 raw IP receive", Enabled: rawIPEnabled, Opener: openIP4Recv, OptionCaps: xio.CapsIP4Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-RECV", Syntax: "IP6-RECV:<protocol>", Desc: "IPv6 raw IP receive", Enabled: rawIPEnabled, Opener: openIP6Recv, OptionCaps: xio.CapsIP6Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-RECVFROM", Syntax: "IP-RECVFROM:<protocol>", Desc: "raw IP recvfrom", Enabled: rawIPEnabled, Opener: openIPRecvfrom, OptionCaps: xio.CapsIPRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-RECVFROM", Syntax: "IP4-RECVFROM:<protocol>", Desc: "IPv4 raw IP recvfrom", Enabled: rawIPEnabled, Opener: openIP4Recvfrom, OptionCaps: xio.CapsIP4Recvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-RECVFROM", Syntax: "IP6-RECVFROM:<protocol>", Desc: "IPv6 raw IP recvfrom", Enabled: rawIPEnabled, Opener: openIP6Recvfrom, OptionCaps: xio.CapsIP6Recvfrom})

	// UNIX and abstract
	unixDgramEnabled := func() bool { return xio.FeatureUNIXDatagram }
	abstractEnabled := func() bool { return xio.FeatureABSTRACT }

	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX", Syntax: "UNIX:<filename>", DynamicDesc: xio.UnixGenericHelp, Opener: openUnixConnect, OptionCaps: xio.CapsUNIXConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-CONNECT", Syntax: "UNIX-CONNECT:<filename>", DynamicDesc: xio.UnixConnectHelp, Opener: openUnixConnect, OptionCaps: xio.CapsUNIXConnect, Aliases: []string{"LOCAL"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-CLIENT", Syntax: "UNIX-CLIENT:<filename>", DynamicDesc: xio.UnixGenericHelp, Opener: openUnixConnect, OptionCaps: xio.CapsUNIXConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-LISTEN", Syntax: "UNIX-LISTEN:<filename>", DynamicDesc: xio.UnixListenHelp, Opener: openUnixListen, OptionCaps: xio.CapsUNIXListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-L", Syntax: "UNIX-L:<filename>", Desc: "same as UNIX-LISTEN", Opener: openUnixListen, OptionCaps: xio.CapsUNIXListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-SENDTO", Syntax: "UNIX-SENDTO:<filename>", Desc: "UNIX datagram sendto", Enabled: unixDgramEnabled, Opener: openUnixSendto, OptionCaps: xio.CapsUNIXConnect, Aliases: []string{"UNIX-SEND"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-RECVFROM", Syntax: "UNIX-RECVFROM:<filename>", Desc: "UNIX datagram recvfrom", Enabled: unixDgramEnabled, Opener: openUnixRecvfrom, OptionCaps: xio.CapsUNIXRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-RECV", Syntax: "UNIX-RECV:<filename>", Desc: "UNIX datagram receive", Enabled: unixDgramEnabled, Opener: openUnixRecv, OptionCaps: xio.CapsUNIXConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-DATAGRAM", Syntax: "UNIX-DATAGRAM:<filename>", Desc: "UNIX datagram with a default write destination; receives from any sender", Enabled: unixDgramEnabled, Opener: openUnixDatagram, OptionCaps: xio.CapsUNIXConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-CONNECT", Syntax: "ABSTRACT-CONNECT:<name>", Desc: "Linux abstract UNIX client", Enabled: abstractEnabled, Opener: openAbstractConnect, OptionCaps: xio.CapsAbstract})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-CLIENT", Syntax: "ABSTRACT-CLIENT:<name>", Desc: "same as ABSTRACT-CONNECT", Enabled: abstractEnabled, Opener: openAbstractConnect, OptionCaps: xio.CapsAbstract, Aliases: []string{"ABSTRACT"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-LISTEN", Syntax: "ABSTRACT-LISTEN:<name>", Desc: "Linux abstract UNIX server", Enabled: abstractEnabled, Opener: openAbstractListen, OptionCaps: xio.CapsAbstractListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-L", Syntax: "ABSTRACT-L:<name>", Desc: "same as ABSTRACT-LISTEN", Enabled: abstractEnabled, Opener: openAbstractListen, OptionCaps: xio.CapsAbstractListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-SENDTO", Syntax: "ABSTRACT-SENDTO:<name>", Desc: "Linux abstract UNIX sendto", Enabled: abstractEnabled, Opener: openAbstractSendto, OptionCaps: xio.CapsAbstract})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-RECVFROM", Syntax: "ABSTRACT-RECVFROM:<name>", Desc: "Linux abstract UNIX recvfrom", Enabled: abstractEnabled, Opener: openAbstractRecvfrom, OptionCaps: xio.CapsAbstractRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-RECV", Syntax: "ABSTRACT-RECV:<name>", Desc: "Linux abstract UNIX receive", Enabled: abstractEnabled, Opener: openAbstractRecv, OptionCaps: xio.CapsAbstract})

	// Generic socket
	socketEnabled := func() bool { return xio.FeatureGENERICSOCKET }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-CONNECT", Syntax: "SOCKET-CONNECT:<dom>:<proto>:<addr>", Desc: "generic socket connect", Enabled: socketEnabled, Opener: openSocketConnect, OptionCaps: xio.CapsSocketConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-LISTEN", Syntax: "SOCKET-LISTEN:<dom>:<proto>:<addr>", Desc: "generic socket listen", Enabled: socketEnabled, Opener: openSocketListen, OptionCaps: xio.CapsSocketListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-SENDTO", Syntax: "SOCKET-SENDTO:<dom>:<type>:<proto>:<addr>", Desc: "generic sendto", Enabled: socketEnabled, Opener: openSocketSendto, OptionCaps: xio.CapsSocketSendto, Aliases: []string{"SENDTO"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-DATAGRAM", Syntax: "SOCKET-DATAGRAM:<dom>:<type>:<proto>:<addr>", Desc: "generic datagram", Enabled: socketEnabled, Opener: openSocketDatagram, OptionCaps: xio.CapsSocketDatagram, Aliases: []string{"DATAGRAM", "DGRAM"}})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-RECV", Syntax: "SOCKET-RECV:<dom>:<type>:<proto>:<addr>", Desc: "generic receive", Enabled: socketEnabled, Opener: openSocketRecv, OptionCaps: xio.CapsSocketDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-RECVFROM", Syntax: "SOCKET-RECVFROM:<dom>:<type>:<proto>:<addr>", Desc: "generic recvfrom", Enabled: socketEnabled, Opener: openSocketRecvfrom, OptionCaps: xio.CapsSocketRecvfrom})

	// SCTP
	sctpEnabled := func() bool { return xio.FeatureSCTP }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP", Syntax: "SCTP:<host>:<port>", Desc: "SCTP client", Enabled: sctpEnabled, Opener: openSCTPConnect, OptionCaps: xio.CapsSCTPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP-CONNECT", Syntax: "SCTP-CONNECT:<host>:<port>", Desc: "same as SCTP", Enabled: sctpEnabled, Opener: openSCTPConnect, OptionCaps: xio.CapsSCTPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP-LISTEN", Syntax: "SCTP-LISTEN:<port>", Desc: "SCTP server", Enabled: sctpEnabled, Opener: openSCTPListen, OptionCaps: xio.CapsSCTPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP-L", Syntax: "SCTP-L:<port>", Desc: "same as SCTP-LISTEN", Enabled: sctpEnabled, Opener: openSCTPListen, OptionCaps: xio.CapsSCTPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4", Syntax: "SCTP4:<host>:<port>", Desc: "IPv4 SCTP client", Enabled: sctpEnabled, Opener: openSCTP4Connect, OptionCaps: xio.CapsSCTP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4-CONNECT", Syntax: "SCTP4-CONNECT:<host>:<port>", Desc: "same as SCTP4", Enabled: sctpEnabled, Opener: openSCTP4Connect, OptionCaps: xio.CapsSCTP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4-LISTEN", Syntax: "SCTP4-LISTEN:<port>", Desc: "IPv4 SCTP server", Enabled: sctpEnabled, Opener: openSCTP4Listen, OptionCaps: xio.CapsSCTP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4-L", Syntax: "SCTP4-L:<port>", Desc: "same as SCTP4-LISTEN", Enabled: sctpEnabled, Opener: openSCTP4Listen, OptionCaps: xio.CapsSCTP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6", Syntax: "SCTP6:<host>:<port>", Desc: "IPv6 SCTP client", Enabled: sctpEnabled, Opener: openSCTP6Connect, OptionCaps: xio.CapsSCTP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6-CONNECT", Syntax: "SCTP6-CONNECT:<host>:<port>", Desc: "same as SCTP6", Enabled: sctpEnabled, Opener: openSCTP6Connect, OptionCaps: xio.CapsSCTP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6-LISTEN", Syntax: "SCTP6-LISTEN:<port>", Desc: "IPv6 SCTP server", Enabled: sctpEnabled, Opener: openSCTP6Listen, OptionCaps: xio.CapsSCTP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6-L", Syntax: "SCTP6-L:<port>", Desc: "same as SCTP6-LISTEN", Enabled: sctpEnabled, Opener: openSCTP6Listen, OptionCaps: xio.CapsSCTP6Listen})

	// VSOCK. -h lists VSOCK-CONNECT and VSOCK-LISTEN; VSOCK / VSOCK-L
	// aliases match SCTP / SCTP-L.
	vsockEnabled := func() bool { return xio.FeatureVSOCK }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK", Syntax: "VSOCK:<cid>:<port>", Desc: "same as VSOCK-CONNECT", Enabled: vsockEnabled, Opener: openVSOCKConnect, OptionCaps: xio.CapsVSOCKConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK-CONNECT", Syntax: "VSOCK-CONNECT:<cid>:<port>", Desc: "VSOCK stream client", Enabled: vsockEnabled, Opener: openVSOCKConnect, OptionCaps: xio.CapsVSOCKConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK-LISTEN", Syntax: "VSOCK-LISTEN:<port>", Desc: "VSOCK stream server", Enabled: vsockEnabled, Opener: openVSOCKListen, OptionCaps: xio.CapsVSOCKListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK-L", Syntax: "VSOCK-L:<port>", Desc: "same as VSOCK-LISTEN", Enabled: vsockEnabled, Opener: openVSOCKListen, OptionCaps: xio.CapsVSOCKListen})
}
