package classiccatalog

// UDPLITE coverage options. The address family is a later Linux-only PR;
// these options stay in the backlog with that family.
var expectedMissingUDPLITE = map[string]Gap{
	"udplite-send-cscov": {Reason: "UDPLITE send coverage (with UDPLITE address family)", Platforms: PlatLinux},
	"udplite-recv-cscov": {Reason: "UDPLITE receive coverage (with UDPLITE address family)", Platforms: PlatLinux},
}
