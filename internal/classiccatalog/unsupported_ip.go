package classiccatalog

// unsupportedGetOnlyIP are classic GROUP_SOCK_IP TYPE_INT OFUNC_SOCKOPT
// setters in xio-ip.c that the kernel does not implement as setsockopt.
// They stay recognized so the CLI can reject them with a precise get-only
// error, but they are not advertised and are not an implementation backlog.
//
// Linux (this host and ip(7)): IP_MTU and IP_PKTOPTIONS return ENOPROTOOPT
// on SET. IP_MTU GET works on a connected IPv4 TCP/UDP socket. IP_PKTOPTIONS
// GET returns a cmsg blob on TCP and ENOPROTOOPT on UDP/raw. Classic still
// models both as setters (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree). Official
// doc/socat.yo documents ip-mtu-discover, not ip-mtu; ip-pktoptions appears
// only as a COMMENT spelling ip-pktopts (not in optionnames[]).
//
// This port follows C/-hhh for the public names and refuses to advertise a
// setter or a silent no-op. ip-hdrincl is implemented (PR A). ip-retopts
// and ip-router-alert are implemented on Linux, not this map.
var unsupportedGetOnlyIP = map[string]string{
	"ip-mtu":        "IP_MTU is get-only (Linux setsockopt ENOPROTOOPT); not implemented as a setter (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"ipmtu":         "alias of ip-mtu; get-only, rejected, not advertised",
	"mtu":           "alias of ip-mtu; get-only, rejected, not advertised",
	"ip-pktoptions": "IP_PKTOPTIONS is get-only (Linux setsockopt ENOPROTOOPT); not implemented as a setter (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"ippktoptions":  "alias of ip-pktoptions; get-only, rejected, not advertised",
	"pktoptions":    "alias of ip-pktoptions; get-only, rejected, not advertised",
	"pktopts":       "alias of ip-pktoptions; get-only, rejected, not advertised",
}
