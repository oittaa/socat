package classiccatalog

// Linux TCP sockopts that classic advertises as TYPE_INT. Probe official
// classic before implementing: several are read-only or need structures.
var expectedMissingTCP = map[string]Gap{
	"tcp-info":   {Reason: "TCP_INFO is a struct; classic TYPE_INT — probe before implementing", Platforms: PlatLinux},
	"info":       {Reason: "alias of tcp-info", Platforms: PlatLinux},
	"tcp-md5sig": {Reason: "TCP_MD5SIG needs a structure; classic TYPE_INT — probe before implementing", Platforms: PlatLinux},
}
