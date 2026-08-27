package netopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	// TCP
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP", Syntax: "TCP:<host>:<port>", Desc: "TCP client", Opener: openTCPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP-CONNECT", Syntax: "TCP-CONNECT:<host>:<port>", Desc: "same as TCP", Opener: openTCPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4", Syntax: "TCP4:<host>:<port>", Desc: "IPv4 TCP client", Opener: openTCP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4-CONNECT", Syntax: "TCP4-CONNECT:<host>:<port>", Desc: "same as TCP4", Opener: openTCP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6", Syntax: "TCP6:<host>:<port>", Desc: "IPv6 TCP client", Opener: openTCP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6-CONNECT", Syntax: "TCP6-CONNECT:<host>:<port>", Desc: "same as TCP6", Opener: openTCP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP-LISTEN", Syntax: "TCP-LISTEN:<port>", Desc: "TCP server", Opener: openTCPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP-L", Syntax: "TCP-L:<port>", Desc: "same as TCP-LISTEN", Opener: openTCPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4-LISTEN", Syntax: "TCP4-LISTEN:<port>", Desc: "IPv4 TCP server", Opener: openTCP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP4-L", Syntax: "TCP4-L:<port>", Desc: "same as TCP4-LISTEN", Opener: openTCP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6-LISTEN", Syntax: "TCP6-LISTEN:<port>", Desc: "IPv6 TCP server", Opener: openTCP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTCP, Name: "TCP6-L", Syntax: "TCP6-L:<port>", Desc: "same as TCP6-LISTEN", Opener: openTCP6Listen})

	// UDP
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP", Syntax: "UDP:<host>:<port>", Desc: "UDP client", Opener: openUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-CONNECT", Syntax: "UDP-CONNECT:<host>:<port>", Desc: "same as UDP", Opener: openUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4", Syntax: "UDP4:<host>:<port>", Desc: "IPv4 UDP client", Opener: openUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-CONNECT", Syntax: "UDP4-CONNECT:<host>:<port>", Desc: "same as UDP4", Opener: openUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6", Syntax: "UDP6:<host>:<port>", Desc: "IPv6 UDP client", Opener: openUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-CONNECT", Syntax: "UDP6-CONNECT:<host>:<port>", Desc: "same as UDP6", Opener: openUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-LISTEN", Syntax: "UDP-LISTEN:<port>", Desc: "UDP server", Opener: openUDPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-L", Syntax: "UDP-L:<port>", Desc: "same as UDP-LISTEN", Opener: openUDPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-LISTEN", Syntax: "UDP4-LISTEN:<port>", Desc: "IPv4 UDP server", Opener: openUDP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-L", Syntax: "UDP4-L:<port>", Desc: "same as UDP4-LISTEN", Opener: openUDP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-LISTEN", Syntax: "UDP6-LISTEN:<port>", Desc: "IPv6 UDP server", Opener: openUDP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-L", Syntax: "UDP6-L:<port>", Desc: "same as UDP6-LISTEN", Opener: openUDP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-SENDTO", Syntax: "UDP-SENDTO:<host>:<port>", Desc: "UDP send to one peer", Opener: openUDPSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-SEND", Syntax: "UDP-SEND:<host>:<port>", Desc: "same as UDP-SENDTO", Opener: openUDPSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-SENDTO", Syntax: "UDP4-SENDTO:<host>:<port>", Desc: "IPv4 UDP send to one peer", Opener: openUDP4Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-SEND", Syntax: "UDP4-SEND:<host>:<port>", Desc: "same as UDP4-SENDTO", Opener: openUDP4Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-SENDTO", Syntax: "UDP6-SENDTO:<host>:<port>", Desc: "IPv6 UDP send to one peer", Opener: openUDP6Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-SEND", Syntax: "UDP6-SEND:<host>:<port>", Desc: "same as UDP6-SENDTO", Opener: openUDP6Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-DATAGRAM", Syntax: "UDP-DATAGRAM:<host>:<port>", Desc: "connected UDP datagram", Opener: openUDPDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-DATAGRAM", Syntax: "UDP4-DATAGRAM:<host>:<port>", Desc: "IPv4 UDP datagram", Opener: openUDP4Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-DATAGRAM", Syntax: "UDP6-DATAGRAM:<host>:<port>", Desc: "IPv6 UDP datagram", Opener: openUDP6Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-RECV", Syntax: "UDP-RECV:<port>", Desc: "receive UDP; ignore source", Opener: openUDPRecv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-RECV", Syntax: "UDP4-RECV:<port>", Desc: "IPv4 UDP receive", Opener: openUDP4Recv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-RECV", Syntax: "UDP6-RECV:<port>", Desc: "IPv6 UDP receive", Opener: openUDP6Recv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP-RECVFROM", Syntax: "UDP-RECVFROM:<port>", Desc: "receive one UDP datagram, reply to sender", Opener: openUDPRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP4-RECVFROM", Syntax: "UDP4-RECVFROM:<port>", Desc: "IPv4 UDP recvfrom", Opener: openUDP4Recvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDP6-RECVFROM", Syntax: "UDP6-RECVFROM:<port>", Desc: "IPv6 UDP recvfrom", Opener: openUDP6Recvfrom})

	// UDP-Lite. Classic xio-udplite.c (tag-1.8.1.3
	// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a is the same file) reuses the
	// UDP CONNECT/LISTEN/SENDTO/RECV/RECVFROM/DATAGRAM openers with
	// SOCK_DGRAM + IPPROTO_UDPLITE. Linux and FreeBSD; -V WITH_UDPLITE.
	udpliteEnabled := func() bool { return xio.FeatureUDPLITE }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE", Syntax: "UDPLITE:<host>:<port>", Desc: "UDP-Lite client", Enabled: udpliteEnabled, Opener: openUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-CONNECT", Syntax: "UDPLITE-CONNECT:<host>:<port>", Desc: "same as UDPLITE", Enabled: udpliteEnabled, Opener: openUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4", Syntax: "UDPLITE4:<host>:<port>", Desc: "IPv4 UDP-Lite client", Enabled: udpliteEnabled, Opener: openUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-CONNECT", Syntax: "UDPLITE4-CONNECT:<host>:<port>", Desc: "same as UDPLITE4", Enabled: udpliteEnabled, Opener: openUDP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6", Syntax: "UDPLITE6:<host>:<port>", Desc: "IPv6 UDP-Lite client", Enabled: udpliteEnabled, Opener: openUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-CONNECT", Syntax: "UDPLITE6-CONNECT:<host>:<port>", Desc: "same as UDPLITE6", Enabled: udpliteEnabled, Opener: openUDP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-LISTEN", Syntax: "UDPLITE-LISTEN:<port>", Desc: "UDP-Lite server", Enabled: udpliteEnabled, Opener: openUDPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-L", Syntax: "UDPLITE-L:<port>", Desc: "same as UDPLITE-LISTEN", Enabled: udpliteEnabled, Opener: openUDPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-LISTEN", Syntax: "UDPLITE4-LISTEN:<port>", Desc: "IPv4 UDP-Lite server", Enabled: udpliteEnabled, Opener: openUDP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-L", Syntax: "UDPLITE4-L:<port>", Desc: "same as UDPLITE4-LISTEN", Enabled: udpliteEnabled, Opener: openUDP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-LISTEN", Syntax: "UDPLITE6-LISTEN:<port>", Desc: "IPv6 UDP-Lite server", Enabled: udpliteEnabled, Opener: openUDP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-L", Syntax: "UDPLITE6-L:<port>", Desc: "same as UDPLITE6-LISTEN", Enabled: udpliteEnabled, Opener: openUDP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-SENDTO", Syntax: "UDPLITE-SENDTO:<host>:<port>", Desc: "UDP-Lite send to one peer", Enabled: udpliteEnabled, Opener: openUDPSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-SEND", Syntax: "UDPLITE-SEND:<host>:<port>", Desc: "same as UDPLITE-SENDTO", Enabled: udpliteEnabled, Opener: openUDPSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-SENDTO", Syntax: "UDPLITE4-SENDTO:<host>:<port>", Desc: "IPv4 UDP-Lite send to one peer", Enabled: udpliteEnabled, Opener: openUDP4Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-SEND", Syntax: "UDPLITE4-SEND:<host>:<port>", Desc: "same as UDPLITE4-SENDTO", Enabled: udpliteEnabled, Opener: openUDP4Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-SENDTO", Syntax: "UDPLITE6-SENDTO:<host>:<port>", Desc: "IPv6 UDP-Lite send to one peer", Enabled: udpliteEnabled, Opener: openUDP6Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-SEND", Syntax: "UDPLITE6-SEND:<host>:<port>", Desc: "same as UDPLITE6-SENDTO", Enabled: udpliteEnabled, Opener: openUDP6Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-DATAGRAM", Syntax: "UDPLITE-DATAGRAM:<host>:<port>", Desc: "UDP-Lite datagram", Enabled: udpliteEnabled, Opener: openUDPDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-DGRAM", Syntax: "UDPLITE-DGRAM:<host>:<port>", Desc: "same as UDPLITE-DATAGRAM", Enabled: udpliteEnabled, Opener: openUDPDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-DATAGRAM", Syntax: "UDPLITE4-DATAGRAM:<host>:<port>", Desc: "IPv4 UDP-Lite datagram", Enabled: udpliteEnabled, Opener: openUDP4Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-DGRAM", Syntax: "UDPLITE4-DGRAM:<host>:<port>", Desc: "same as UDPLITE4-DATAGRAM", Enabled: udpliteEnabled, Opener: openUDP4Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-DATAGRAM", Syntax: "UDPLITE6-DATAGRAM:<host>:<port>", Desc: "IPv6 UDP-Lite datagram", Enabled: udpliteEnabled, Opener: openUDP6Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-DGRAM", Syntax: "UDPLITE6-DGRAM:<host>:<port>", Desc: "same as UDPLITE6-DATAGRAM", Enabled: udpliteEnabled, Opener: openUDP6Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-RECV", Syntax: "UDPLITE-RECV:<port>", Desc: "receive UDP-Lite; ignore source", Enabled: udpliteEnabled, Opener: openUDPRecv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-RECV", Syntax: "UDPLITE4-RECV:<port>", Desc: "IPv4 UDP-Lite receive", Enabled: udpliteEnabled, Opener: openUDP4Recv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-RECV", Syntax: "UDPLITE6-RECV:<port>", Desc: "IPv6 UDP-Lite receive", Enabled: udpliteEnabled, Opener: openUDP6Recv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE-RECVFROM", Syntax: "UDPLITE-RECVFROM:<port>", Desc: "receive one UDP-Lite datagram, reply to sender", Enabled: udpliteEnabled, Opener: openUDPRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE4-RECVFROM", Syntax: "UDPLITE4-RECVFROM:<port>", Desc: "IPv4 UDP-Lite recvfrom", Enabled: udpliteEnabled, Opener: openUDP4Recvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUDP, Name: "UDPLITE6-RECVFROM", Syntax: "UDPLITE6-RECVFROM:<port>", Desc: "IPv6 UDP-Lite recvfrom", Enabled: udpliteEnabled, Opener: openUDP6Recvfrom})

	// Raw IP
	rawIPEnabled := func() bool { return xio.FeatureRAWIP }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP", Syntax: "IP:<host>:<protocol>", Desc: "raw IP send/receive", Enabled: rawIPEnabled, Opener: openIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4", Syntax: "IP4:<host>:<protocol>", Desc: "IPv4 raw IP", Enabled: rawIPEnabled, Opener: openIP4})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6", Syntax: "IP6:<host>:<protocol>", Desc: "IPv6 raw IP", Enabled: rawIPEnabled, Opener: openIP6})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-SENDTO", Syntax: "IP-SENDTO:<host>:<protocol>", Desc: "raw IP send to one peer", Enabled: rawIPEnabled, Opener: openIPSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-SENDTO", Syntax: "IP4-SENDTO:<host>:<protocol>", Desc: "IPv4 raw IP sendto", Enabled: rawIPEnabled, Opener: openIP4Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-SENDTO", Syntax: "IP6-SENDTO:<host>:<protocol>", Desc: "IPv6 raw IP sendto", Enabled: rawIPEnabled, Opener: openIP6Sendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-DATAGRAM", Syntax: "IP-DATAGRAM:<host>:<protocol>", Desc: "raw IP datagram", Enabled: rawIPEnabled, Opener: openIPDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-DATAGRAM", Syntax: "IP4-DATAGRAM:<host>:<protocol>", Desc: "IPv4 raw IP datagram", Enabled: rawIPEnabled, Opener: openIP4Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-DATAGRAM", Syntax: "IP6-DATAGRAM:<host>:<protocol>", Desc: "IPv6 raw IP datagram", Enabled: rawIPEnabled, Opener: openIP6Datagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-RECV", Syntax: "IP-RECV:<protocol>", Desc: "raw IP receive", Enabled: rawIPEnabled, Opener: openIPRecv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-RECV", Syntax: "IP4-RECV:<protocol>", Desc: "IPv4 raw IP receive", Enabled: rawIPEnabled, Opener: openIP4Recv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-RECV", Syntax: "IP6-RECV:<protocol>", Desc: "IPv6 raw IP receive", Enabled: rawIPEnabled, Opener: openIP6Recv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP-RECVFROM", Syntax: "IP-RECVFROM:<protocol>", Desc: "raw IP recvfrom", Enabled: rawIPEnabled, Opener: openIPRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP4-RECVFROM", Syntax: "IP4-RECVFROM:<protocol>", Desc: "IPv4 raw IP recvfrom", Enabled: rawIPEnabled, Opener: openIP4Recvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupRawIP, Name: "IP6-RECVFROM", Syntax: "IP6-RECVFROM:<protocol>", Desc: "IPv6 raw IP recvfrom", Enabled: rawIPEnabled, Opener: openIP6Recvfrom})

	// UNIX and abstract
	unixDgramEnabled := func() bool { return xio.FeatureUNIXDatagram }
	abstractEnabled := func() bool { return xio.FeatureABSTRACT }

	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX", Syntax: "UNIX:<filename>", DynamicDesc: xio.UnixGenericHelp, Opener: openUnixConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-CONNECT", Syntax: "UNIX-CONNECT:<filename>", DynamicDesc: xio.UnixConnectHelp, Opener: openUnixConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-CLIENT", Syntax: "UNIX-CLIENT:<filename>", DynamicDesc: xio.UnixGenericHelp, Opener: openUnixConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-LISTEN", Syntax: "UNIX-LISTEN:<filename>", DynamicDesc: xio.UnixListenHelp, Opener: openUnixListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-L", Syntax: "UNIX-L:<filename>", Desc: "same as UNIX-LISTEN", Opener: openUnixListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-SENDTO", Syntax: "UNIX-SENDTO:<filename>", Desc: "UNIX datagram sendto", Enabled: unixDgramEnabled, Opener: openUnixSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-RECVFROM", Syntax: "UNIX-RECVFROM:<filename>", Desc: "UNIX datagram recvfrom", Enabled: unixDgramEnabled, Opener: openUnixRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-RECV", Syntax: "UNIX-RECV:<filename>", Desc: "UNIX datagram receive", Enabled: unixDgramEnabled, Opener: openUnixRecv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "UNIX-DATAGRAM", Syntax: "UNIX-DATAGRAM:<filename>", Desc: "UNIX datagram", Enabled: unixDgramEnabled, Opener: openUnixDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-CONNECT", Syntax: "ABSTRACT-CONNECT:<name>", Desc: "Linux abstract UNIX client", Enabled: abstractEnabled, Opener: openAbstractConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-CLIENT", Syntax: "ABSTRACT-CLIENT:<name>", Desc: "same as ABSTRACT-CONNECT", Enabled: abstractEnabled, Opener: openAbstractConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-LISTEN", Syntax: "ABSTRACT-LISTEN:<name>", Desc: "Linux abstract UNIX server", Enabled: abstractEnabled, Opener: openAbstractListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-L", Syntax: "ABSTRACT-L:<name>", Desc: "same as ABSTRACT-LISTEN", Enabled: abstractEnabled, Opener: openAbstractListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-SENDTO", Syntax: "ABSTRACT-SENDTO:<name>", Desc: "Linux abstract UNIX sendto", Enabled: abstractEnabled, Opener: openAbstractSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-RECVFROM", Syntax: "ABSTRACT-RECVFROM:<name>", Desc: "Linux abstract UNIX recvfrom", Enabled: abstractEnabled, Opener: openAbstractRecvfrom})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupUnix, Name: "ABSTRACT-RECV", Syntax: "ABSTRACT-RECV:<name>", Desc: "Linux abstract UNIX receive", Enabled: abstractEnabled, Opener: openAbstractRecv})

	// Generic socket
	socketEnabled := func() bool { return xio.FeatureGENERICSOCKET }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-CONNECT", Syntax: "SOCKET-CONNECT:<dom>:<proto>:<addr>", Desc: "generic socket connect", Enabled: socketEnabled, Opener: openSocketConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-LISTEN", Syntax: "SOCKET-LISTEN:<dom>:<proto>:<addr>", Desc: "generic socket listen", Enabled: socketEnabled, Opener: openSocketListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-SENDTO", Syntax: "SOCKET-SENDTO:<dom>:<type>:<proto>:<addr>", Desc: "generic sendto", Enabled: socketEnabled, Opener: openSocketSendto})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-DATAGRAM", Syntax: "SOCKET-DATAGRAM:<dom>:<type>:<proto>:<addr>", Desc: "generic datagram", Enabled: socketEnabled, Opener: openSocketDatagram})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-RECV", Syntax: "SOCKET-RECV:<dom>:<type>:<proto>:<addr>", Desc: "generic receive", Enabled: socketEnabled, Opener: openSocketRecv})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSocket, Name: "SOCKET-RECVFROM", Syntax: "SOCKET-RECVFROM:<dom>:<type>:<proto>:<addr>", Desc: "generic recvfrom", Enabled: socketEnabled, Opener: openSocketRecvfrom})

	// SCTP
	sctpEnabled := func() bool { return xio.FeatureSCTP }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP", Syntax: "SCTP:<host>:<port>", Desc: "SCTP client", Enabled: sctpEnabled, Opener: openSCTPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP-CONNECT", Syntax: "SCTP-CONNECT:<host>:<port>", Desc: "same as SCTP", Enabled: sctpEnabled, Opener: openSCTPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP-LISTEN", Syntax: "SCTP-LISTEN:<port>", Desc: "SCTP server", Enabled: sctpEnabled, Opener: openSCTPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP-L", Syntax: "SCTP-L:<port>", Desc: "same as SCTP-LISTEN", Enabled: sctpEnabled, Opener: openSCTPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4", Syntax: "SCTP4:<host>:<port>", Desc: "IPv4 SCTP client", Enabled: sctpEnabled, Opener: openSCTP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4-CONNECT", Syntax: "SCTP4-CONNECT:<host>:<port>", Desc: "same as SCTP4", Enabled: sctpEnabled, Opener: openSCTP4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4-LISTEN", Syntax: "SCTP4-LISTEN:<port>", Desc: "IPv4 SCTP server", Enabled: sctpEnabled, Opener: openSCTP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP4-L", Syntax: "SCTP4-L:<port>", Desc: "same as SCTP4-LISTEN", Enabled: sctpEnabled, Opener: openSCTP4Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6", Syntax: "SCTP6:<host>:<port>", Desc: "IPv6 SCTP client", Enabled: sctpEnabled, Opener: openSCTP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6-CONNECT", Syntax: "SCTP6-CONNECT:<host>:<port>", Desc: "same as SCTP6", Enabled: sctpEnabled, Opener: openSCTP6Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6-LISTEN", Syntax: "SCTP6-LISTEN:<port>", Desc: "IPv6 SCTP server", Enabled: sctpEnabled, Opener: openSCTP6Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupSCTP, Name: "SCTP6-L", Syntax: "SCTP6-L:<port>", Desc: "same as SCTP6-LISTEN", Enabled: sctpEnabled, Opener: openSCTP6Listen})

	// VSOCK. Classic -h lists VSOCK-CONNECT and VSOCK-LISTEN; addressnames[]
	// also accepts VSOCK / VSOCK-L (same as SCTP / SCTP-L).
	vsockEnabled := func() bool { return xio.FeatureVSOCK }
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK", Syntax: "VSOCK:<cid>:<port>", Desc: "same as VSOCK-CONNECT", Enabled: vsockEnabled, Opener: openVSOCKConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK-CONNECT", Syntax: "VSOCK-CONNECT:<cid>:<port>", Desc: "VSOCK stream client", Enabled: vsockEnabled, Opener: openVSOCKConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK-LISTEN", Syntax: "VSOCK-LISTEN:<port>", Desc: "VSOCK stream server", Enabled: vsockEnabled, Opener: openVSOCKListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupVSOCK, Name: "VSOCK-L", Syntax: "VSOCK-L:<port>", Desc: "same as VSOCK-LISTEN", Enabled: vsockEnabled, Opener: openVSOCKListen})
}
