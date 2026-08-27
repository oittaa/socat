package classiccatalog

// unsupportedClassicUnimplemented holds documented public spellings that
// official classic socat never implemented. They stay in
// DocsOnlyNotInThisBinary (so they remain RequiredPublicSpellings) and are
// classified unsupported: not advertised, not ImplementationBacklog.
//
// udp-ignore-peerport is documented in official doc/socat.yo
// (OPTION_UDP_IGNORE_PEERPORT). tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba and official master
// af5388c898c7bb60997935aee93c223deba60c4a do not register it in
// optionnames[] and have no implementation call site. Classic currently
// rejects the spelling as unknown.
//
// Classic C DATAGRAM (xio-udp.c / xioread.c, matched by #101) accepts any
// sender by default and applies range/tcpwrap/lowport; sourceport is a
// dest-port receive filter, not a bind. SENDTO still requires the configured
// peer. The man page describes udp-ignore-peerport as "configured peer IP,
// any source port", which implies a default exact-peer check that the C
// DATAGRAM path does not do.
//
// There is no way to honor the man-page wording while retaining classic C
// behavior: advertising a no-op violates the no-advertised-no-op rule;
// inventing default peer-port filtering would undo #101 and diverge from C.
// Do not implement this spelling without an explicit compatibility decision.
var unsupportedClassicUnimplemented = map[string]string{
	"udp-ignore-peerport": "documented OPTION_UDP_IGNORE_PEERPORT; classic C never implemented it (man/C disagreement). Not backlog; do not advertise or implement without an explicit compatibility decision (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
}
