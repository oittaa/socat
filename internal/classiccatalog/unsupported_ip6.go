package classiccatalog

// unsupportedBlobIP6 are classic GROUP_SOCK_IP6 TYPE_INT OFUNC_SOCKOPT
// names whose kernel objects are extension-header blobs or sendmsg
// structures. The public integer syntax cannot represent them safely, so
// they are not advertised and are not an implementation backlog.
//
// Linux setsockopt(int) fails (EINVAL / ENOPROTOOPT / EPERM). Do not add
// fake integer setters. ipv6-pktinfo is not the IPv4 pktinfo / ip-pktinfo
// option. ipv6-hoplimit is not ipv6-unicast-hops or ipv6-recvhoplimit.
//
// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same option table.
var unsupportedBlobIP6 = map[string]string{
	"ipv6-authhdr":  "IPV6_AUTHHDR/DSTOPTS is an extension-header blob; public TYPE_INT syntax cannot represent it (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"authhdr":       "alias of ipv6-authhdr; blob, rejected, not advertised",
	"ipv6-dstopts":  "IPV6_DSTOPTS is an extension-header blob; public TYPE_INT syntax cannot represent it (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"dstopts":       "alias of ipv6-dstopts; blob, rejected, not advertised",
	"ipv6-hoplimit": "IPV6_HOPLIMIT is a cmsg/sendmsg item, not a TYPE_INT setsockopt; use ipv6-unicast-hops / ipv6-recvhoplimit (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"hoplimit":      "alias of ipv6-hoplimit; not a TYPE_INT setter, rejected, not advertised",
	"ipv6-hopopts":  "IPV6_HOPOPTS is an extension-header blob; public TYPE_INT syntax cannot represent it (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"hopopts":       "alias of ipv6-hopopts; blob, rejected, not advertised",
	"ipv6-pktinfo":  "IPV6_PKTINFO is struct in6_pktinfo, not a TYPE_INT setter; ipv6-recvpktinfo is the recv flag (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"ipv6-rthdr":    "IPV6_RTHDR is a routing-header blob; public TYPE_INT syntax cannot represent it (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"rthdr":         "alias of ipv6-rthdr; blob, rejected, not advertised",
}
