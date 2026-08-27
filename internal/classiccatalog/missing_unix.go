package classiccatalog

var expectedMissingUNIX = map[string]Gap{
	"unix-tightsocklen": {Reason: "UNIX sun_path tight sockaddr length", Platforms: PlatUnix},
	"tightsocklen":      {Reason: "alias of unix-tightsocklen", Platforms: PlatUnix},
}
