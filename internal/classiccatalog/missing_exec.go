package classiccatalog

// EXEC / FORK child options. FeatureEXEC is Unix-only.
var expectedMissingExec = map[string]Gap{
	"dash":    {Reason: "EXEC dash/login argv0 rewrite", Platforms: PlatUnix},
	"login":   {Reason: "alias of dash", Platforms: PlatUnix},
	"setpgid": {Reason: "FORK setpgid", Platforms: PlatUnix},
	"pgid":    {Reason: "alias of setpgid", Platforms: PlatUnix},
}
