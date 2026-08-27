package classiccatalog

// Process/privilege options. Later work must not call setuid/setgid/chroot
// from a session goroutine; they stay in the backlog until a worker-process
// design or an explicit architecture/security README exception exists.
var expectedMissingProcess = map[string]Gap{
	"chroot":            {Reason: "PROCESS chroot (requires isolation design)", Platforms: PlatUnix},
	"chroot-early":      {Reason: "PROCESS chroot-early (requires isolation design)", Platforms: PlatUnix},
	"setgid":            {Reason: "PROCESS setgid (requires isolation design)", Platforms: PlatUnix},
	"setgid-early":      {Reason: "PROCESS setgid-early (requires isolation design)", Platforms: PlatUnix},
	"setuid":            {Reason: "PROCESS setuid (requires isolation design)", Platforms: PlatUnix},
	"setuid-early":      {Reason: "PROCESS setuid-early (requires isolation design)", Platforms: PlatUnix},
	"substuser":         {Reason: "PROCESS substuser (groups and environment)", Platforms: PlatUnix},
	"su":                {Reason: "alias of substuser", Platforms: PlatUnix},
	"substuser-delayed": {Reason: "PROCESS substuser-delayed", Platforms: PlatUnix},
	"su-d":              {Reason: "alias of substuser-delayed", Platforms: PlatUnix},
	"substuser-early":   {Reason: "PROCESS substuser-early", Platforms: PlatUnix},
	"su-e":              {Reason: "alias of substuser-early", Platforms: PlatUnix},
}
