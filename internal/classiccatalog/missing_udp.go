package classiccatalog

// udp-ignore-peerport (PR B). Official doc/socat.yo documents it; tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba and official master
// af5388c898c7bb60997935aee93c223deba60c4a do not register it in optionnames[]
// and have no implementation call site. The documented interface is
// authoritative: implement the man-page behavior, do not advertise until then.
var expectedMissingUDP = map[string]Gap{
	"udp-ignore-peerport": {
		Reason:    "documented UDP-DATAGRAM option; not in optionnames[] (PR B)",
		Platforms: PlatAll,
	},
}
