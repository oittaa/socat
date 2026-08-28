package classiccatalog

// Resolver / getaddrinfo options. Later resolver work; do not claim exact
// libc res_state retry/search semantics where Go does not expose them.
var expectedMissingResolver = map[string]Gap{
	"ai-all":         {Reason: "AI_ALL", Platforms: PlatAll},
	"ai-passive":     {Reason: "AI_PASSIVE", Platforms: PlatAll},
	"passive":        {Reason: "alias of ai-passive", Platforms: PlatAll},
	"ai-v4mapped":    {Reason: "AI_V4MAPPED", Platforms: PlatAll},
	"v4mapped":       {Reason: "alias of ai-v4mapped", Platforms: PlatAll},
	"res-debug":      {Reason: "RES_DEBUG", Platforms: PlatUnix},
	"res-defnames":   {Reason: "RES_DEFNAMES", Platforms: PlatUnix},
	"defnames":       {Reason: "alias of res-defnames", Platforms: PlatUnix},
	"res-dnsrch":     {Reason: "RES_DNSRCH", Platforms: PlatUnix},
	"dnsrch":         {Reason: "alias of res-dnsrch", Platforms: PlatUnix},
	"res-igntc":      {Reason: "RES_IGNTC", Platforms: PlatUnix},
	"igntc":          {Reason: "alias of res-igntc", Platforms: PlatUnix},
	"res-recurse":    {Reason: "RES_RECURSE", Platforms: PlatUnix},
	"recurse":        {Reason: "alias of res-recurse", Platforms: PlatUnix},
	"res-retrans":    {Reason: "resolver retrans", Platforms: PlatUnix},
	"res-maxretrans": {Reason: "alias of res-retrans", Platforms: PlatUnix},
	"retrans":        {Reason: "alias of res-retrans", Platforms: PlatUnix},
	"res-retry":      {Reason: "resolver retry", Platforms: PlatUnix},
	"res-maxretry":   {Reason: "alias of res-retry", Platforms: PlatUnix},
	"res-stayopen":   {Reason: "RES_STAYOPEN", Platforms: PlatUnix},
	"stayopen":       {Reason: "alias of res-stayopen", Platforms: PlatUnix},
	"res-usevc":      {Reason: "RES_USEVC", Platforms: PlatUnix},
	"usevc":          {Reason: "alias of res-usevc", Platforms: PlatUnix},
}
