package classiccatalog

// Remaining INTERFACE / TUN flags (later iff-* work). retrieve-vlan is implemented.
var expectedMissingInterface = map[string]Gap{
	"iff-automedia":  {Reason: "IFF_AUTOMEDIA on INTERFACE/TUN", Platforms: PlatLinux},
	"automedia":      {Reason: "alias of iff-automedia", Platforms: PlatLinux},
	"iff-master":     {Reason: "IFF_MASTER on INTERFACE/TUN", Platforms: PlatLinux},
	"master":         {Reason: "alias of iff-master", Platforms: PlatLinux},
	"iff-notrailers": {Reason: "IFF_NOTRAILERS on INTERFACE/TUN", Platforms: PlatLinux},
	"notrailers":     {Reason: "alias of iff-notrailers", Platforms: PlatLinux},
	"iff-portsel":    {Reason: "IFF_PORTSEL on INTERFACE/TUN", Platforms: PlatLinux},
	"portsel":        {Reason: "alias of iff-portsel", Platforms: PlatLinux},
	"iff-slave":      {Reason: "IFF_SLAVE on INTERFACE/TUN", Platforms: PlatLinux},
	"slave":          {Reason: "alias of iff-slave", Platforms: PlatLinux},
	"iff-dynamic":    {Reason: "documented IFF_DYNAMIC; commented out of classic optionnames[]", Platforms: PlatLinux},
}
