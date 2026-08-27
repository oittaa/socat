package classiccatalog

// SCTP options (PR G). Documented in official doc/socat.yo; the Linux
// reference dump omitted them when SCTP_NODELAY/SCTP_MAXSEG were not in
// that binary's headers. Linux SCTP sockets only.
var expectedMissingSCTP = map[string]Gap{
	"sctp-nodelay": {Reason: "SCTP_NODELAY at PH_PASTSOCKET (PR G)", Platforms: PlatLinux},
	"sctp-maxseg":  {Reason: "SCTP_MAXSEG at PH_PASTSOCKET (PR G)", Platforms: PlatLinux},
}
