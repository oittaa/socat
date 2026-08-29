package classiccatalog

// unsupportedSocketIoctl is the SOL_SOCKET / ioctl audit (PR D). Classic
// advertises these public spellings (optionnames[] / -hhh) at tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same xio-socket.c /
// xioopts.c / doc/socat.yo tree. This port does not advertise them as
// setters or no-ops; they stay out of ImplementationBacklog.
//
// so-error / so-acceptconn: OFUNC_SOCKOPT TYPE_INT. Official man COMMENTs
// so-error as read-only and so-acceptconn as “tries to set SO_ACCEPTCONN”.
// Linux setsockopt(SO_ERROR) and setsockopt(SO_ACCEPTCONN) return
// ENOPROTOOPT; getsockopt works. Advertising a setter would be a no-op or
// a hard error for every value.
//
// so-peercred: OFUNC_SOCKOPT TYPE_INT3 (ucred). xioopts.c parseopts_table
// case TYPE_INT3 is #if LATER (empty). Classic cannot parse a value; -hhh
// still prints type=INT[3]. Man COMMENT: “This is a read-only socket option.”
//
// so-attach-filter: OFUNC_SOCKOPT TYPE_INT. The kernel wants struct
// sock_fprog, not an int. A TYPE_INT setsockopt is not a BPF program.
// Inventing a filter language would need an explicit compatibility
// decision (same rule as udp-ignore-peerport). so-detach-filter is not a
// useful public interface without attach.
//
// so-security-*: obsolete IPSec-era SO_SECURITY_* (ENOPROTOOPT).
//
// Implemented in this audit, not this map: fiosetown / siocspgrp
// (OFUNC_IOCTL pointer-to-int).
var unsupportedSocketIoctl = map[string]string{ // #nosec G101 -- classic option names and reasons, not secrets
	"so-error":                         "SO_ERROR is get-only; classic TYPE_INT setsockopt is ENOPROTOOPT (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a). Not advertised as a setter",
	"error":                            "alias of so-error; get-only, not advertised as a setter",
	"so-acceptconn":                    "SO_ACCEPTCONN is get-only; classic TYPE_INT setsockopt is ENOPROTOOPT (same SHAs). Not advertised as a setter",
	"acceptconn":                       "alias of so-acceptconn; get-only, not advertised as a setter",
	"so-peercred":                      "SO_PEERCRED is a ucred struct; classic TYPE_INT3 parser is #if LATER (unparseable) and man marks it read-only (same SHAs). Not advertised as a setter",
	"peercred":                         "alias of so-peercred; get-only, not advertised as a setter",
	"so-attach-filter":                 "SO_ATTACH_FILTER needs struct sock_fprog; classic TYPE_INT cannot honor it (same SHAs). Not advertised; do not invent a filter language without an explicit compatibility decision",
	"attach-filter":                    "alias of so-attach-filter; not advertised",
	"attachfilter":                     "alias of so-attach-filter; not advertised",
	"so-detach-filter":                 "SO_DETACH_FILTER is not a useful public interface without attach (same SHAs). Not advertised",
	"detach-filter":                    "alias of so-detach-filter; not advertised",
	"detachfilter":                     "alias of so-detach-filter; not advertised",
	"so-security-authentication":       "obsolete SO_SECURITY_AUTHENTICATION; Linux ENOPROTOOPT (same SHAs). Not advertised",
	"security-authentication":          "alias of so-security-authentication; not advertised",
	"securityauthentication":           "alias of so-security-authentication; not advertised",
	"so-security-encryption-network":   "obsolete SO_SECURITY_ENCRYPTION_NETWORK; Linux ENOPROTOOPT (same SHAs). Not advertised",
	"security-encryption-network":      "alias of so-security-encryption-network; not advertised",
	"securityencryptionnetwork":        "alias of so-security-encryption-network; not advertised",
	"so-security-encryption-transport": "obsolete SO_SECURITY_ENCRYPTION_TRANSPORT; Linux ENOPROTOOPT (same SHAs). Not advertised",
	"security-encryption-transport":    "alias of so-security-encryption-transport; not advertised",
	"securityencryptiontransport":      "alias of so-security-encryption-transport; not advertised",
}
