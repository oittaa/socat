package classiccatalog

// IPv6 extension-header and get-only cmsg options. Later remaining-IP work
// must not represent get-only names as setters.
var expectedMissingIP6 = map[string]Gap{
	"ipv6-authhdr":     {Reason: "IPV6_DSTOPTS/AUTHHDR extension header", Platforms: PlatUnix},
	"authhdr":          {Reason: "alias of ipv6-authhdr", Platforms: PlatUnix},
	"ipv6-dstopts":     {Reason: "IPV6_DSTOPTS", Platforms: PlatUnix},
	"dstopts":          {Reason: "alias of ipv6-dstopts", Platforms: PlatUnix},
	"ipv6-hoplimit":    {Reason: "IPV6_HOPLIMIT send-side", Platforms: PlatUnix},
	"hoplimit":         {Reason: "alias of ipv6-hoplimit", Platforms: PlatUnix},
	"ipv6-hopopts":     {Reason: "IPV6_HOPOPTS", Platforms: PlatUnix},
	"hopopts":          {Reason: "alias of ipv6-hopopts", Platforms: PlatUnix},
	"ipv6-pktinfo":     {Reason: "IPV6_PKTINFO send-side", Platforms: PlatUnix},
	"ipv6-recvdstopts": {Reason: "IPV6_RECVDSTOPTS", Platforms: PlatUnix},
	"recvdstopts":      {Reason: "alias of ipv6-recvdstopts", Platforms: PlatUnix},
	"ipv6-recvhopopts": {Reason: "IPV6_RECVHOPOPTS", Platforms: PlatUnix},
	"recvhopopts":      {Reason: "alias of ipv6-recvhopopts", Platforms: PlatUnix},
	"ipv6-recvpathmtu": {Reason: "IPV6_RECVPATHMTU", Platforms: PlatUnix},
	"ipv6-recvrthdr":   {Reason: "IPV6_RECVRTHDR", Platforms: PlatUnix},
	"recvrthdr":        {Reason: "alias of ipv6-recvrthdr", Platforms: PlatUnix},
	"ipv6-rthdr":       {Reason: "IPV6_RTHDR", Platforms: PlatUnix},
	"rthdr":            {Reason: "alias of ipv6-rthdr", Platforms: PlatUnix},
}
