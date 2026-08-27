package classiccatalog

// Named SOL_SOCKET options not yet implemented. Probe low-water and
// read-only sockopts on each OS before advertising; do not advertise a no-op.
// so-bsdcompat is unsupportedNoopSockopts, not this map.
var expectedMissingSocket = map[string]Gap{
	"so-rcvlowat":                      {Reason: "SO_RCVLOWAT; probe before advertising", Platforms: PlatUnix},
	"rcvlowat":                         {Reason: "alias of so-rcvlowat", Platforms: PlatUnix},
	"so-sndlowat":                      {Reason: "SO_SNDLOWAT; probe before advertising", Platforms: PlatUnix},
	"sndlowat":                         {Reason: "alias of so-sndlowat", Platforms: PlatUnix},
	"so-error":                         {Reason: "SO_ERROR is get-only; classic passes an int — probe before implementing", Platforms: PlatUnix},
	"error":                            {Reason: "alias of so-error", Platforms: PlatUnix},
	"so-acceptconn":                    {Reason: "SO_ACCEPTCONN is get-only; classic passes an int — probe before implementing", Platforms: PlatUnix},
	"acceptconn":                       {Reason: "alias of so-acceptconn", Platforms: PlatUnix},
	"so-peercred":                      {Reason: "SO_PEERCRED is a ucred struct; classic TYPE_INT[3] — probe before implementing", Platforms: PlatLinux},
	"peercred":                         {Reason: "alias of so-peercred", Platforms: PlatLinux},
	"so-attach-filter":                 {Reason: "SO_ATTACH_FILTER (BPF)", Platforms: PlatLinux},
	"attach-filter":                    {Reason: "alias of so-attach-filter", Platforms: PlatLinux},
	"attachfilter":                     {Reason: "alias of so-attach-filter", Platforms: PlatLinux},
	"so-detach-filter":                 {Reason: "SO_DETACH_FILTER", Platforms: PlatLinux},
	"detach-filter":                    {Reason: "alias of so-detach-filter", Platforms: PlatLinux},
	"detachfilter":                     {Reason: "alias of so-detach-filter", Platforms: PlatLinux},
	"so-security-authentication":       {Reason: "obsolete SO_SECURITY_AUTHENTICATION", Platforms: PlatLinux},
	"security-authentication":          {Reason: "alias of so-security-authentication", Platforms: PlatLinux},
	"securityauthentication":           {Reason: "alias of so-security-authentication", Platforms: PlatLinux},
	"so-security-encryption-network":   {Reason: "obsolete SO_SECURITY_ENCRYPTION_NETWORK", Platforms: PlatLinux},
	"security-encryption-network":      {Reason: "alias of so-security-encryption-network", Platforms: PlatLinux},
	"securityencryptionnetwork":        {Reason: "alias of so-security-encryption-network", Platforms: PlatLinux},
	"so-security-encryption-transport": {Reason: "obsolete SO_SECURITY_ENCRYPTION_TRANSPORT", Platforms: PlatLinux},
	"security-encryption-transport":    {Reason: "alias of so-security-encryption-transport", Platforms: PlatLinux},
	"securityencryptiontransport":      {Reason: "alias of so-security-encryption-transport", Platforms: PlatLinux},
	"fiosetown":                        {Reason: "FIOSETOWN", Platforms: PlatUnix},
	"siocspgrp":                        {Reason: "SIOCSPGRP", Platforms: PlatUnix},
}
