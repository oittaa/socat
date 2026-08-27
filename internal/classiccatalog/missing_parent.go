package classiccatalog

// PARENT signal policy for EXEC children.
var expectedMissingParent = map[string]Gap{
	"sighup":  {Reason: "PARENT SIGHUP policy for EXEC", Platforms: PlatUnix},
	"sigint":  {Reason: "PARENT SIGINT policy for EXEC", Platforms: PlatUnix},
	"sigquit": {Reason: "PARENT SIGQUIT policy for EXEC", Platforms: PlatUnix},
}
