package classiccatalog

// IPv4/IPv6 settable sockopts still unimplemented (not the recv ancillary
// matrix already shipped). Later remaining-IP work.
var expectedMissingIP = map[string]Gap{
	"ip-hdrincl":      {Reason: "IP_HDRINCL", Platforms: PlatUnix},
	"hdrincl":         {Reason: "alias of ip-hdrincl", Platforms: PlatUnix},
	"iphdrincl":       {Reason: "alias of ip-hdrincl", Platforms: PlatUnix},
	"ip-mtu":          {Reason: "IP_MTU", Platforms: PlatUnix},
	"ipmtu":           {Reason: "alias of ip-mtu", Platforms: PlatUnix},
	"mtu":             {Reason: "alias of ip-mtu", Platforms: PlatUnix},
	"ip-pktoptions":   {Reason: "IP_PKTOPTIONS", Platforms: PlatUnix},
	"ippktoptions":    {Reason: "alias of ip-pktoptions", Platforms: PlatUnix},
	"pktoptions":      {Reason: "alias of ip-pktoptions", Platforms: PlatUnix},
	"pktopts":         {Reason: "alias of ip-pktoptions", Platforms: PlatUnix},
	"ip-retopts":      {Reason: "IP_RETOPTS", Platforms: PlatUnix},
	"ipretopts":       {Reason: "alias of ip-retopts", Platforms: PlatUnix},
	"retopts":         {Reason: "alias of ip-retopts", Platforms: PlatUnix},
	"ip-router-alert": {Reason: "IP_ROUTER_ALERT", Platforms: PlatUnix},
	"iprouteralert":   {Reason: "alias of ip-router-alert", Platforms: PlatUnix},
	"routeralert":     {Reason: "alias of ip-router-alert", Platforms: PlatUnix},
}
