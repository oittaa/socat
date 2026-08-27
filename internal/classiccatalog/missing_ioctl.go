package classiccatalog

// Generic ioctl family (PR I). Unix only; GROUP_FD.
var expectedMissingIOCTL = map[string]Gap{
	"ioctl":        {Reason: "alias of ioctl-void (PR I)", Platforms: PlatUnix},
	"ioctl-void":   {Reason: "generic ioctl request with no argument (PR I)", Platforms: PlatUnix},
	"ioctl-int":    {Reason: "generic ioctl with int argument (PR I)", Platforms: PlatUnix},
	"ioctl-intp":   {Reason: "generic ioctl with int pointer argument (PR I)", Platforms: PlatUnix},
	"ioctl-bin":    {Reason: "generic ioctl with binary payload (PR I)", Platforms: PlatUnix},
	"ioctl-string": {Reason: "generic ioctl with string payload (PR I)", Platforms: PlatUnix},
}
