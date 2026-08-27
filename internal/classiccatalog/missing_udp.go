package classiccatalog

// udp-ignore-peerport is documented in official doc/socat.yo. tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba and official master
// af5388c898c7bb60997935aee93c223deba60c4a do not register it in optionnames[]
// and have no implementation call site.
//
// Classic C DATAGRAM (xio-udp.c / xioread.c, matched by #101) accepts any
// sender by default and applies range/tcpwrap/lowport; sourceport is a
// dest-port receive filter, not a bind. SENDTO still requires the configured
// peer. The man page describes udp-ignore-peerport as "configured peer IP,
// any source port", which implies a default exact-peer check that the C
// DATAGRAM path does not do. Keep this spelling in the backlog as documented
// public interface; do not revert #101's any-sender DATAGRAM default to
// invent that exact-peer default.
var expectedMissingUDP = map[string]Gap{
	"udp-ignore-peerport": {
		Reason:    "documented UDP-DATAGRAM option; not in optionnames[] (man/C disagreement; see file comment)",
		Platforms: PlatAll,
	},
}
