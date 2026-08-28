package classiccatalog

// Remaining INTERFACE / TUN names. iff-dynamic is unsupportedClassicUnimplemented
// (documented, commented out of classic optionnames[]). retrieve-vlan is a later PR.
var expectedMissingInterface = map[string]Gap{
	"retrieve-vlan": {Reason: "PACKET_AUXDATA VLAN reconstruction on AF_PACKET", Platforms: PlatLinux},
}
